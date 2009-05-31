/*
 * (C) 2008 Zeng Zhaorong
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
/*
 * Derived from linux netfilter conntrack codes
 */

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <net/ip.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define nf_proto_csum_replace4	inet_proto_csum_replace4
#define NF_IP_PRE_ROUTING	NF_INET_PRE_ROUTING
#define NF_IP_POST_ROUTING	NF_INET_POST_ROUTING
#endif

#include "daemon_kernel.h"

#define TCPTRACK_VERSION "0.0.1"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wheelz");
MODULE_DESCRIPTION("Drcom-Kernel " TCPTRACK_VERSION);

enum tcp_state {
	TCP_STATE_NONE = 0,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECV,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSE,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_LAST_ACK,
	TCP_STATE_LISTEN,
	TCP_STATE_MAX
};

#define SECS *HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS
#define DAYS * 24 HOURS

static unsigned long tcp_timeouts[]
= { 30 MINS,    /*      TCP_STATE_NONE, */
    2 MINS,     /*      TCP_STATE_SYN_SENT,     */
    60 SECS,    /*      TCP_STATE_SYN_RECV,     */
    5 DAYS,     /*      TCP_STATE_ESTABLISHED,  */
    2 MINS,     /*      TCP_STATE_FIN_WAIT,     */
    2 MINS,     /*      TCP_STATE_TIME_WAIT,    */
    10 SECS,    /*      TCP_STATE_CLOSE,	*/
    60 SECS,    /*      TCP_STATE_CLOSE_WAIT,   */
    30 SECS,    /*      TCP_STATE_LAST_ACK,     */
    2 MINS,     /*      TCP_STATE_LISTEN,       */
};

#define sNO TCP_STATE_NONE
#define sES TCP_STATE_ESTABLISHED
#define sSS TCP_STATE_SYN_SENT
#define sSR TCP_STATE_SYN_RECV
#define sFW TCP_STATE_FIN_WAIT
#define sTW TCP_STATE_TIME_WAIT
#define sCL TCP_STATE_CLOSE
#define sCW TCP_STATE_CLOSE_WAIT
#define sLA TCP_STATE_LAST_ACK
#define sLI TCP_STATE_LISTEN
#define sIV TCP_STATE_MAX

static enum tcp_state tcp_states[2][5][TCP_STATE_MAX] = {
	{
/*      ORIGINAL */
/*	sNO, sSS, sSR, sES, sFW, sTW, sCL, sCW, sLA, sLI      */
/*syn*/ {sSS, sSS, sSR, sES, sSS, sSS, sSS, sSS, sSS, sLI },
/*fin*/ {sTW, sSS, sTW, sFW, sFW, sTW, sCL, sTW, sLA, sLI },
/*ack*/ {sES, sSS, sES, sES, sFW, sTW, sCL, sCW, sLA, sES },
/*rst*/ {sCL, sSS, sCL, sCL, sCL, sTW, sCL, sCL, sCL, sCL },
/*none*/{sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	},
	{
/*      REPLY */
/*	sNO, sSS, sSR, sES, sFW, sTW, sCL, sCW, sLA, sLI      */
/*syn*/ {sSR, sSR, sSR, sES, sSR, sSR, sSR, sSR, sSR, sSR },
/*fin*/ {sCL, sSS, sTW, sCW, sTW, sTW, sCL, sCW, sLA, sLI },
/*ack*/ {sCL, sSS, sSR, sES, sFW, sTW, sCL, sCW, sCL, sLI },
/*rst*/ {sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sLA, sLI },
/*none*/{sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
	}
};

struct tcp_tuple
{
	__be32	src_ip;
	__be32	dst_ip;

	__be16	src_port;
	__be16	dst_port;

	u_int8_t	dir;
};

struct tcp_tuplehash
{
	struct list_head 	list;
	struct tcp_tuple	tuple;
};

struct tcp_seq
{
	u_int32_t	syn_seq;
	u_int32_t	correction_pos;
	int16_t 	offset_before, offset_after;
};

struct tcp_conn
{
	struct tcp_tuplehash	tuplehash[2];

	atomic_t 		ref;

	struct timer_list	timeout;

	u_int8_t		flags;
	enum tcp_state		state;
	struct tcp_seq		seq[2];
};

#define CONN_F_NEW	0x01
#define CONN_F_AUTHSENT	0x02

#define TODO_NONE	0x00
#define TODO_ADJUST_SEQ	0x01
#define TODO_SEND_ACK	0x02
#define TODO_SEND_AUTH	0x04

#define CONN_DIR_ORIG	0
#define CONN_DIR_REPLY	1

#define TCP_CONN_HASH_SIZE	32

static pid_t	conn_pid = 0;
static int	conn_autologout = 0;
static struct timer_list conn_keepalive_timer;

static unsigned char conn_auth_data[CONN_AUTH_DATA_LEN];

static struct list_head		tcp_conn_hash[TCP_CONN_HASH_SIZE];

static atomic_t	tcp_conn_count = ATOMIC_INIT(0);

static struct net_device 	*track_dev = NULL;
static struct e_address		*conn_e_addr = NULL;
static int conn_e_count = 0;

static int track_mode = CONN_MODE_NONE;

static DEFINE_RWLOCK(mode_lock);
static DEFINE_RWLOCK(hash_lock);
static DEFINE_RWLOCK(state_lock);

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

#if 0
static const char *tcp_state_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN"
};
#endif

static inline int tuple_equal(struct tcp_tuple *t1, struct tcp_tuple *t2)
{
	return (t1->src_ip == t2->src_ip && t1->dst_ip == t2->dst_ip
	       && t1->src_port == t2->src_port && t1->dst_port == t2->dst_port);
}

static inline u_int32_t hash_conn(const struct tcp_tuple *tuple) 
{
	return (ntohl(tuple->src_ip + tuple->dst_ip + tuple->src_port + tuple->dst_port) 
		+ ntohs(tuple->src_port)) % TCP_CONN_HASH_SIZE;
}

static inline struct tcp_conn *tuplehash_to_conn(const struct tcp_tuplehash *hash)
{
	return container_of(hash, struct tcp_conn, tuplehash[hash->tuple.dir]);
}

static inline void conn_get(struct tcp_conn *conn)
{
	if (conn)
		atomic_inc(&conn->ref);
}

static inline void conn_put(struct tcp_conn *conn)
{
	if (conn && atomic_dec_and_test(&conn->ref)) {
		kfree(conn);
		atomic_dec(&tcp_conn_count);
	}
}

/* under state_lock */
static void __conn_refresh_timer(struct tcp_conn *conn, unsigned long timeout)
{
	unsigned long newtime;

	if (conn->flags & CONN_F_NEW) {
		conn->flags &= ~CONN_F_NEW;
		conn->timeout.expires = jiffies + timeout;
		add_timer(&conn->timeout);
	} else {
		newtime = jiffies + timeout;
		if (newtime - conn->timeout.expires >= HZ && del_timer(&conn->timeout)) {
			conn->timeout.expires = newtime;
			add_timer(&conn->timeout);
		}
	}
}

static void death_by_timeout(unsigned long ul_conn)
{
	struct tcp_conn *conn = (struct tcp_conn*)ul_conn;

	write_lock_bh(&hash_lock);
	list_del(&conn->tuplehash[CONN_DIR_ORIG].list);
	list_del(&conn->tuplehash[CONN_DIR_REPLY].list);
	write_unlock_bh(&hash_lock);

	conn_put(conn);
}

static void conn_tuple_init(struct tcp_conn *conn, struct tcp_tuple *tuple)
{
	struct tcp_tuple *t;

	t = &conn->tuplehash[CONN_DIR_ORIG].tuple;
	t->src_ip = tuple->src_ip;
	t->dst_ip = tuple->dst_ip;
	t->src_port = tuple->src_port;
	t->dst_port = tuple->dst_port;
	t->dir = CONN_DIR_ORIG;
		
	t = &conn->tuplehash[CONN_DIR_REPLY].tuple;
	t->src_ip = tuple->dst_ip;
	t->dst_ip = tuple->src_ip;
	t->src_port = tuple->dst_port;
	t->dst_port = tuple->src_port;
	t->dir = CONN_DIR_REPLY;
}

static inline struct tcp_conn *get_new_conn(struct tcp_tuple *tuple)
{
	struct tcp_conn *conn;

	conn = kmalloc(sizeof(struct tcp_conn), GFP_ATOMIC);
	if (conn == NULL)
		return NULL;

	memset(conn, 0, sizeof(struct tcp_conn));

	conn->flags = CONN_F_NEW;
	conn_tuple_init(conn, tuple);
	setup_timer(&conn->timeout, death_by_timeout, (unsigned long)conn);

	return conn;
}

static int is_syn_pkt(struct sk_buff *skb)
{
	unsigned int nhoff = skb_network_offset(skb);
	struct iphdr *iph, _iph;
	struct tcphdr *tcph, _tcph;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return 0;

	tcph = skb_header_pointer(skb, nhoff + (iph->ihl << 2), sizeof(_tcph), &_tcph); 
	if (tcph == NULL)
		return 0;

	return (tcph->syn && !tcph->ack);
}

static int tcp_get_tuple(struct sk_buff *skb, struct tcp_tuple *tuple)
{
	struct iphdr _iph, *iph;
	struct tcphdr _hdr, *hp;
	unsigned int nhoff = skb_network_offset(skb);
	unsigned int thoff;

	memset(tuple, 0, sizeof(struct tcp_tuple));

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return 0;

	tuple->src_ip = iph->saddr;
	tuple->dst_ip = iph->daddr;

	thoff = nhoff + (iph->ihl << 2);

	hp = skb_header_pointer(skb, thoff, 8, &_hdr);
	if (hp == NULL)
		return 0;

	tuple->src_port = hp->source;
	tuple->dst_port = hp->dest;

	return 1;
}

static inline void __add_new_hash(struct tcp_tuplehash *hash)
{
	u_int32_t h = hash_conn(&hash->tuple);
	struct list_head *head = &tcp_conn_hash[h];

	list_add_tail(&hash->list, head);
}

static struct tcp_tuplehash *__hash_find(struct tcp_tuple *tuple)
{
	struct tcp_tuplehash *tuplehash;
	struct list_head *head, *pos;
	u_int32_t h;

	h = hash_conn(tuple);
	head = &tcp_conn_hash[h];

	list_for_each(pos, head) {
		tuplehash = list_entry(pos, struct tcp_tuplehash, list);
		if (tuple_equal(&tuplehash->tuple, tuple))
			return tuplehash;
	}

	return NULL;
}

static struct tcp_tuplehash *resolve_tcp_conn(struct sk_buff *skb)
{
	struct tcp_tuple tuple;
	struct tcp_conn *conn;
	struct tcp_tuplehash *hash;

	if (!tcp_get_tuple(skb, &tuple))
		return NULL;

	read_lock_bh(&hash_lock);
	hash = __hash_find(&tuple);
	if (hash != NULL) {
		conn = tuplehash_to_conn(hash);
		conn_get(conn);
		read_unlock_bh(&hash_lock);
		return hash;
	}
	read_unlock_bh(&hash_lock);

	/* OK, This is a new connection, let's create a conn */

	/* the first packet must be SYN && !ACK */
	if (!is_syn_pkt(skb))
		return NULL;

	conn = get_new_conn(&tuple);
	if (conn == NULL)
		return NULL;

	conn_get(conn);/* for this packet */
	conn_get(conn);/* for hash list */

	write_lock_bh(&hash_lock);
	hash = __hash_find(&tuple);
	if (hash != NULL) { /* already added by someone else, but is it possible?  */
		struct tcp_conn *conn2 = tuplehash_to_conn(hash);
		conn_get(conn2);
		write_unlock_bh(&hash_lock);
		conn_put(conn); /* for hash list */
		conn_put(conn); /* for this packet */
		return hash;
	}

	__add_new_hash(&conn->tuplehash[CONN_DIR_ORIG]);
	__add_new_hash(&conn->tuplehash[CONN_DIR_REPLY]);
	
	write_unlock_bh(&hash_lock);

	atomic_inc(&tcp_conn_count);

	hash = &conn->tuplehash[CONN_DIR_ORIG];

	return hash;
}

static void sack_adjust(struct sk_buff *skb, struct tcphdr *tcph, 
		unsigned int sackoff, unsigned int sackend, struct tcp_seq *seq)
{
	while (sackoff < sackend) {
		struct tcp_sack_block_wire *sack;
		__be32 new_start_seq, new_end_seq;

		sack = (void *)skb->data + sackoff;
		if (after(ntohl(sack->start_seq) - seq->offset_before, seq->correction_pos))
			new_start_seq = htonl(ntohl(sack->start_seq) - seq->offset_after);
		else
			new_start_seq = htonl(ntohl(sack->start_seq) - seq->offset_before);

		if (after(ntohl(sack->end_seq) - seq->offset_before, seq->correction_pos))
			new_end_seq = htonl(ntohl(sack->end_seq) - seq->offset_after);
		else
			new_end_seq = htonl(ntohl(sack->end_seq) - seq->offset_before);

		DEBUGP("sack_adjust: start_seq: %d->%d, end_seq: %d->%d\n",
			 ntohl(sack->start_seq), ntohl(new_start_seq), ntohl(sack->end_seq), ntohl(new_end_seq));

		nf_proto_csum_replace4(&tcph->check, skb, sack->start_seq, new_start_seq, 0);
		nf_proto_csum_replace4(&tcph->check, skb, sack->end_seq, new_end_seq, 0);
		sack->start_seq = new_start_seq;
		sack->end_seq = new_end_seq;
		sackoff += sizeof(*sack);
	}
}

static int tcp_sack_adjust(struct tcp_conn *conn, int dir, struct sk_buff *skb, struct tcphdr *tcph)
{
	unsigned int optoff, optend;

	optoff = ip_hdrlen(skb) + sizeof(struct tcphdr);
	optend = ip_hdrlen(skb) + tcph->doff * 4;

	if (!skb_make_writable(skb, optend))
		return 0;

	while (optoff < optend) {
		/* Usually: option, length. */
		unsigned char *op = skb->data + optoff;

		switch (op[0]) {
		case TCPOPT_EOL:
			return 1;
		case TCPOPT_NOP:
			optoff++;
			continue;
		default:
			/* no partial options */
			if (optoff + 1 == optend || optoff + op[1] > optend || op[1] < 2)
				return 0;
			if (op[0] == TCPOPT_SACK && op[1] >= 2+TCPOLEN_SACK_PERBLOCK &&
			    ((op[1] - 2) % TCPOLEN_SACK_PERBLOCK) == 0)
				sack_adjust(skb, tcph, optoff+2, optoff+op[1], &conn->seq[!dir]);
			optoff += op[1];
		}
	}
	return 1;
}

static int tcp_adjust_seq(struct sk_buff *skb, struct tcp_tuplehash *hash)
{
	struct tcp_conn *conn = tuplehash_to_conn(hash);
	int dir = hash->tuple.dir;
	struct tcphdr *tcph;
	__be32 newseq, newack;
	struct tcp_seq *this_way, *other_way;
	int ret = 0;

	read_lock_bh(&state_lock);

	this_way = &conn->seq[dir];
	other_way = &conn->seq[!dir];

	if (!skb_make_writable(skb, ip_hdrlen(skb) + sizeof(*tcph)))
		goto out;

	tcph = (void *)skb->data + ip_hdrlen(skb);
	if (after(ntohl(tcph->seq), this_way->correction_pos))
		newseq = htonl(ntohl(tcph->seq) + this_way->offset_after);
	else
		newseq = htonl(ntohl(tcph->seq) + this_way->offset_before);

	if (after(ntohl(tcph->ack_seq) - other_way->offset_before, other_way->correction_pos))
		newack = htonl(ntohl(tcph->ack_seq) - other_way->offset_after);
	else
		newack = htonl(ntohl(tcph->ack_seq) - other_way->offset_before);

	if (newseq != tcph->seq) {
		nf_proto_csum_replace4(&tcph->check, skb, tcph->seq, newseq, 0);
		tcph->seq = newseq;
	}
	if (newack != tcph->ack_seq) {
		nf_proto_csum_replace4(&tcph->check, skb, tcph->ack_seq, newack, 0);
		tcph->ack_seq = newack;

		if (!tcp_sack_adjust(conn, dir, skb, tcph))
			goto out;
	}

	ret = 1;
out:
	read_unlock_bh(&state_lock);
	return ret;
}

static unsigned int get_state_index(const struct tcphdr *tcph)
{
	if (tcph->rst) {return 3;}
	else if (tcph->syn) {return 0;}
	else if (tcph->fin) {return 1;}
	else if (tcph->ack) {return 2;}
	else {return 4;}
}

/* return what to do */
static unsigned int check_tcp_packet(struct sk_buff *skb, struct tcp_tuplehash *hash)
{
	enum tcp_state newstate, oldtcpstate;
	struct tcp_conn *conn = tuplehash_to_conn(hash);
	int dir = hash->tuple.dir;
	unsigned int nhoff = skb_network_offset(skb);
	struct iphdr *iph, _iph;
	struct tcphdr *tcph, _tcph;
	unsigned int hdrlen;
	struct tcp_seq *seq;
	u_int8_t todo = TODO_NONE;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return TODO_NONE;

	tcph = skb_header_pointer(skb, nhoff + (iph->ihl << 2), sizeof(_tcph), &_tcph); 
	if (tcph == NULL)
		return TODO_NONE;

	hdrlen = (iph->ihl + tcph->doff)*4;
	if (skb->len < hdrlen) {/* we may not have the options */
		DEBUGP("tcp_packet: Truncated packet.\n");
		return TODO_NONE;
	}

	write_lock_bh(&state_lock);

	oldtcpstate = conn->state;
	newstate = tcp_states[dir][get_state_index(tcph)][oldtcpstate];

	if (newstate == TCP_STATE_MAX) { /* invalid */
		DEBUGP("tcp_packet: Invalid dir=%i index=%u state=%s\n",
				dir, get_state_index(tcph), tcp_state_names[conn->state]);
		write_unlock_bh(&state_lock);
		return TODO_NONE;
	}

	conn->state = newstate;

	if (conn->flags & CONN_F_AUTHSENT) {
		todo = TODO_ADJUST_SEQ;
		goto out;
	}

	/* Handshake SYN */
	if (oldtcpstate == TCP_STATE_NONE && dir == CONN_DIR_ORIG && tcph->syn && !tcph->ack) {
		seq = &conn->seq[dir];
		seq->syn_seq = ntohl(tcph->seq);
		seq->correction_pos = seq->syn_seq;
		seq->offset_before = 0;
		seq->offset_after = CONN_AUTH_DATA_LEN;
		todo = TODO_NONE;
		goto out;
	}

	/* Handshake SYN-ACK */
	if (oldtcpstate == TCP_STATE_SYN_SENT && dir == CONN_DIR_REPLY && tcph->syn && tcph->ack) {
		seq = &conn->seq[dir];
		seq->syn_seq = ntohl(tcph->seq);
		seq->correction_pos = seq->syn_seq;
		seq->offset_before = 0;
		seq->offset_after = 0;
		todo = TODO_NONE;
		goto out;
	}

	/* Handshake pure ACK: we don't care this case actually */
	/*
	if (oldtcpstate == TCP_STATE_SYN_RECV && skb->len == hdrlen && dir == CONN_DIR_ORIG 
		&& tcph->ack && !tcph->syn && ntohl(tcph->ack_seq) == conn->seq[!dir].syn_seq+1)
	{
		todo = TODO_NONE;
		goto out;
	}
	*/

	/* Handshake ACK with data*/
	if (oldtcpstate == TCP_STATE_SYN_RECV && skb->len > hdrlen && dir == CONN_DIR_ORIG
		    && tcph->ack && !tcph->syn 
		    && (ntohl(tcph->ack_seq) == conn->seq[!dir].syn_seq+1)
		    && (ntohl(tcph->seq) == conn->seq[dir].syn_seq+1)
		    && !(conn->flags & CONN_F_AUTHSENT))
	{
		todo = TODO_SEND_ACK | TODO_SEND_AUTH | TODO_ADJUST_SEQ;
		conn->flags |= CONN_F_AUTHSENT;
		goto out;
	}

	/* The first data packet */
	if (oldtcpstate == TCP_STATE_ESTABLISHED && skb->len > hdrlen && dir == CONN_DIR_ORIG
		    && tcph->ack && !tcph->syn 
		/*    && (ntohl(tcph->ack_seq) == conn->seq[!dir].syn_seq+1) *//* ftp server will send first */
		    && (ntohl(tcph->seq) == conn->seq[dir].syn_seq+1)
		    && !(conn->flags & CONN_F_AUTHSENT))
	{
		todo = TODO_SEND_AUTH | TODO_ADJUST_SEQ;
		conn->flags |= CONN_F_AUTHSENT;
		goto out;
	}

	/*
	 * CONN_F_AUTHSENT not set, 
	 * and not the case to set CONN_F_AUTHSENT, 
	 * just bypass
	 */
	todo = TODO_NONE;

out:
	__conn_refresh_timer(conn, tcp_timeouts[newstate]);

	write_unlock_bh(&state_lock);

	return todo;
}

static struct sk_buff *build_ack_skb(struct sk_buff *oskb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sk_buff *skb;

	/* FIXME: Can we avoid the copy here? */
	skb = skb_copy(oskb, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	iph = ip_hdr(skb);
	tcph = (void *)skb->data + ip_hdrlen(skb);

	skb_trim(skb, (iph->ihl + tcph->doff) * 4);

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;

	tcph->check = 0;
	tcph->check = tcp_v4_check(tcph->doff << 2, iph->saddr, iph->daddr, 
					csum_partial((char *)tcph, tcph->doff << 2, skb->csum));

	iph->tot_len = htons(skb->len);
	__ip_select_ident(iph, skb->dst, 0);
	ip_send_check(iph);

	return skb;
}

static struct sk_buff *build_auth_skb(struct sk_buff *oskb)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int hdrlen;
	struct sk_buff *skb;

	/* FIXME: Can we avoid the copy here? */
	skb = skb_copy_expand(oskb, skb_headroom(oskb), CONN_AUTH_DATA_LEN, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	iph = ip_hdr(skb);
	tcph = (void *)skb->data + ip_hdrlen(skb);
	hdrlen = (iph->ihl + tcph->doff) * 4;

	skb_trim(skb, hdrlen);
	skb_put(skb, CONN_AUTH_DATA_LEN);
	memcpy(skb->data + hdrlen, conn_auth_data, CONN_AUTH_DATA_LEN);

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;

	tcph->check = 0;
	tcph->check = tcp_v4_check(skb->len-ip_hdrlen(skb), iph->saddr, iph->daddr, 
					csum_partial((char *)tcph, skb->len-ip_hdrlen(skb), skb->csum));

	iph->tot_len = htons(skb->len);
	__ip_select_ident(iph, skb->dst, 0);
	ip_send_check(iph);

	return skb;
}

static inline int is_our_packet(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	return (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP);
}

static inline int is_udp_packet(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	return (iph->protocol == IPPROTO_UDP);
}

static void conn_do_udp(struct sk_buff *oskb, int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned short len;

	/* FIXME: Can we avoid the copy here? */
	skb = skb_copy_expand(oskb, skb_headroom(oskb) + CONN_AUTH_DATA_LEN, 0, GFP_ATOMIC);
	if (skb == NULL)
		return;

	kfree_skb(oskb);

	iph = ip_hdr(skb);
	udph = (void *)iph + ip_hdrlen(skb);
	memcpy((void *)iph-CONN_AUTH_DATA_LEN, (void*)iph, ip_hdrlen(skb)+8);
	memcpy((void*)udph+8-CONN_AUTH_DATA_LEN, conn_auth_data, CONN_AUTH_DATA_LEN);

	skb_push(skb, CONN_AUTH_DATA_LEN);
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	udph = (void *)iph + ip_hdrlen(skb);

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;

	len = ntohs(udph->len) + CONN_AUTH_DATA_LEN;
	udph->len = htons(len);

	udph->check = 0;
	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len, IPPROTO_UDP, 
					csum_partial((unsigned char *)udph, len, 0));

	/* ip stuff */
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

	okfn(skb);
}

static int need_auth_input(struct sk_buff *skb)
{
	u_int32_t saddr = ip_hdr(skb)->saddr;
	int i;

	for (i=0; i<conn_e_count; i++) 
		if ((conn_e_addr[i].mask & saddr) == conn_e_addr[i].addr)
			return 0;

	return 1;
}

static int need_auth_output(struct sk_buff *skb)
{
	u_int32_t daddr = ip_hdr(skb)->daddr;
	int i;

	for (i=0; i<conn_e_count; i++) 
		if ((conn_e_addr[i].mask & daddr) == conn_e_addr[i].addr)
			return 0;

	return 1;
}

#define CONN_KEEPALIVE_TIMEOUT	(2*60*HZ)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#define kill_proc(pid, sig, priv)	kill_pid(find_vpid(pid), sig, priv)
#endif

static void keepalive_func(unsigned long ul)
{
	read_lock_bh(&mode_lock);
	if (track_mode != CONN_MODE_NONE && conn_autologout && conn_pid)
		kill_proc(conn_pid, SIGUSR1, 1);
	read_unlock_bh(&mode_lock);
}

static void init_keepalive_timer(void)
{
	read_lock_bh(&mode_lock);
	if (track_mode != CONN_MODE_NONE && conn_autologout) {
		setup_timer(&conn_keepalive_timer, keepalive_func, 0);
		conn_keepalive_timer.expires = jiffies+CONN_KEEPALIVE_TIMEOUT;
		add_timer(&conn_keepalive_timer);
	}
	read_unlock_bh(&mode_lock);
}

/* under mode_lock */
static void __refresh_keepalive_timer(void)
{
	if (conn_autologout)
		mod_timer(&conn_keepalive_timer, jiffies+CONN_KEEPALIVE_TIMEOUT);
}

static void del_keepalive_timer(void)
{
	read_lock_bh(&mode_lock);
	del_timer(&conn_keepalive_timer);
	read_unlock_bh(&mode_lock);
}

static unsigned int preroute_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct tcp_tuplehash *hash;
	unsigned int todo;

	read_lock_bh(&mode_lock);

	if (track_mode == CONN_MODE_NONE)
		goto out_unlock;

	if (in != track_dev || !is_our_packet(skb))
		goto out_unlock;

	if (!need_auth_input(skb))
		goto out_unlock;

	__refresh_keepalive_timer();

	if (is_udp_packet(skb)) {
		/* 
		 * we need do nothing here
		 */
		read_unlock_bh(&mode_lock);
		return NF_ACCEPT;
	}

	hash = resolve_tcp_conn(skb);
	if (hash == NULL)
		goto out_unlock;

	todo = check_tcp_packet(skb, hash);

	if (todo & TODO_ADJUST_SEQ)
		(void)tcp_adjust_seq(skb, hash);

	conn_put(tuplehash_to_conn(hash));

out_unlock:
	read_unlock_bh(&mode_lock);

	return NF_ACCEPT;
}

static unsigned int postroute_hook(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
	struct tcp_tuplehash *hash;
	unsigned int todo;
	struct sk_buff *skb2;

	read_lock_bh(&mode_lock);

	if (track_mode == CONN_MODE_NONE)
		goto out_unlock;

	if (out != track_dev || !is_our_packet(skb))
		goto out_unlock;

	if (!need_auth_output(skb))
		goto out_unlock;

	__refresh_keepalive_timer();

	if (is_udp_packet(skb)) {
		conn_do_udp(skb, okfn);
		read_unlock_bh(&mode_lock);
		return NF_STOLEN;
	}

	hash = resolve_tcp_conn(skb);
	if (hash == NULL)
		goto out_unlock;

	todo = check_tcp_packet(skb, hash);

	if (todo & TODO_SEND_ACK) {
		skb2 = build_ack_skb(skb);
		if (skb2 != NULL)
			okfn(skb2);
	}

	if (todo & TODO_SEND_AUTH) {
		skb2 = build_auth_skb(skb);
		if (skb2 != NULL)
			okfn(skb2);
	}

	if (todo & TODO_ADJUST_SEQ)
		(void)tcp_adjust_seq(skb, hash);

	conn_put(tuplehash_to_conn(hash));

out_unlock:
	read_unlock_bh(&mode_lock);

	return NF_ACCEPT;
}

static struct nf_hook_ops preroute_hook_ops = {
	.hook = preroute_hook,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_IP_PRE_ROUTING,
	.priority = NF_IP_PRI_CONNTRACK_DEFRAG+1,
};

static struct nf_hook_ops postroute_hook_ops = {
	.hook = postroute_hook,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_IP_POST_ROUTING,
	.priority = NF_IP_PRI_LAST,
};

static void conn_hash_cleanup(void)
{
	struct tcp_conn *conn;
	struct tcp_tuplehash *h;
	int i;

	/* free tcp_conn hash memory */
i_see_dead_people:
	while (1) {
		conn = NULL;
		write_lock_bh(&hash_lock);
		for (i=0; i<TCP_CONN_HASH_SIZE; i++) {
			struct list_head *head = &tcp_conn_hash[i];
			if (!list_empty(head)){
				h = list_entry(head->next, struct tcp_tuplehash, list);
				conn = tuplehash_to_conn(h);
				conn_get(conn);
				break;
			}
		}
		write_unlock_bh(&hash_lock);

		if (conn == NULL)
			break;

		if (del_timer(&conn->timeout)) {
			death_by_timeout((unsigned long)conn);
			conn_put(conn);
		}
	}

	while (atomic_read(&tcp_conn_count) != 0) {
		schedule();
		goto i_see_dead_people;
	}

}

static int conn_hooks_init(void)
{
	int ret;

	ret = nf_register_hook(&preroute_hook_ops);
	if(ret < 0){
		printk(KERN_ERR "PRE-ROUTE hook register failed\n");
		goto out_err;
	}

	ret = nf_register_hook(&postroute_hook_ops);
	if(ret < 0){
		printk(KERN_ERR "POST-ROUTE hook register failed\n");
		goto out_unregister_1;
	}

	return 0;

out_unregister_1:
	nf_unregister_hook(&preroute_hook_ops);
out_err:
	return ret;
}

static void conn_hooks_cleanup(void)
{
	nf_unregister_hook(&postroute_hook_ops);
	nf_unregister_hook(&preroute_hook_ops);

	synchronize_net();
}

static int conn_set_params(struct sock *sk, int optname, void *optval, unsigned int optlen)
{
	struct conn_param cp;
	struct net_device *dev, *tmp_dev = NULL;
	struct e_address *e_addr=NULL, *tmp_addr;
	unsigned int e_len;
	int i;

	if (optlen < sizeof(struct conn_param))
		return -EINVAL;

	if (copy_from_user(&cp, optval, sizeof(struct conn_param)))
		return -EFAULT;

	if (cp.e_count < 0)
		return -EINVAL;

	if (cp.e_count > 0) {
		e_len = cp.e_count * sizeof(struct e_address);

		if (optlen < sizeof(struct conn_param) + e_len)
			return -EINVAL;

		e_addr = kmalloc(e_len, GFP_KERNEL);
		if (e_addr == NULL)
			return -ENOMEM;

		if (copy_from_user(e_addr, optval+sizeof(struct conn_param), e_len)) {
			kfree(e_addr);
			return -EFAULT;
		}
	}

	dev = dev_get_by_name(&init_net, cp.devname);
	if (dev == NULL) {
		if (e_addr)
			kfree(e_addr);
		return -ENODEV;
	}

	write_lock_bh(&mode_lock);

	tmp_addr = conn_e_addr;
	conn_e_count = cp.e_count;
	if (conn_e_count != 0) {
		conn_e_addr = e_addr;

		for(i=0; i<conn_e_count; i++) 
			conn_e_addr[i].addr &= conn_e_addr[i].mask;
	}

	tmp_dev = track_dev;
	track_dev = dev;

	write_unlock_bh(&mode_lock);

	if (tmp_addr)
		kfree(tmp_addr);
	if (tmp_dev)
		dev_put(tmp_dev);

	return 0;
}

static int conn_set_auth_cmd(struct sock *sk, int optname, void *optval, unsigned int optlen)
{
	struct conn_auth_cmd cmd;
	int hash_todo = 0;

	if (optlen < sizeof(struct conn_auth_cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(struct conn_auth_cmd)))
		return -EFAULT;

	rtnl_lock();

	write_lock_bh(&mode_lock);

	if (track_mode == CONN_MODE_NONE && cmd.cmd == CONN_MODE_AUTH) {
		track_mode = cmd.cmd;
		conn_pid = cmd.pid;
		conn_autologout = cmd.autologout;
		memcpy(conn_auth_data, cmd.auth_data, CONN_AUTH_DATA_LEN);
		hash_todo = 1; /* conn_hooks_init() */
	} else if (track_mode == CONN_MODE_AUTH && cmd.cmd == CONN_MODE_NONE) {
		track_mode = cmd.cmd;
		conn_pid = 0;
		conn_autologout = 0;
		memset(conn_auth_data, 0, CONN_AUTH_DATA_LEN);
		hash_todo = 2; /* conn_hooks_cleanup */
	} else {
		DEBUGP("Same Auth Cmd\n");
	}

	write_unlock_bh(&mode_lock);

	if (hash_todo == 1) {
		init_keepalive_timer();
		conn_hooks_init();
		printk(KERN_INFO "Drcom-Kernel: Authentication Started.\n");
	} else if (hash_todo == 2) {
		del_keepalive_timer();
		conn_hooks_cleanup();
		conn_hash_cleanup();
		printk(KERN_INFO "Drcom-Kernel: Authentication Stopped.\n");
	}

	rtnl_unlock();

	return 0;
}

static int conn_set_sockopt(struct sock *sk, int optname, void *optval, unsigned int optlen)
{
	switch (optname) {
	case CONN_SO_SET_PARAMS: /* set addresses of no need to auth */
		return conn_set_params(sk, optname, optval, optlen);

	case CONN_SO_SET_AUTH_CMD: /* set auth data, and start auth */
		return conn_set_auth_cmd(sk, optname, optval, optlen);

	default:
		return -ENOPROTOOPT;
	}

	return -ENOPROTOOPT;
}

static struct nf_sockopt_ops conn_so_ops = {
	.pf	     = PF_INET,
	.set_optmin     = CONN_SO_BASE_CTL,
	.set_optmax     = CONN_SO_SET_MAX+1,
	.set	    = &conn_set_sockopt,
	.owner	  = THIS_MODULE,
};

static int __init init(void)
{
	int ret;
	int i;

	for (i=0; i<TCP_CONN_HASH_SIZE; i++)
		INIT_LIST_HEAD(&tcp_conn_hash[i]);

	ret = nf_register_sockopt(&conn_so_ops);
	if(ret != 0)
		return ret;

	printk(KERN_INFO "Drcom-Kernel " TCPTRACK_VERSION " module loaded\n");

	return ret;
}

static void __exit fini(void)
{
	int do_dirty_work=0;

	nf_unregister_sockopt(&conn_so_ops);

	rtnl_lock();

	write_lock_bh(&mode_lock);
	if (track_mode == CONN_MODE_AUTH)
		do_dirty_work = 1;
	track_mode = CONN_MODE_NONE;
	write_unlock_bh(&mode_lock);

	if (do_dirty_work) {
		conn_hooks_cleanup();
		conn_hash_cleanup();
	}

	rtnl_unlock();

	if (conn_e_addr)
		kfree(conn_e_addr);
	if (track_dev)
		dev_put(track_dev);

	printk(KERN_INFO "Drcom-Kernel " TCPTRACK_VERSION " module unloaded\n");
}

module_init(init);
module_exit(fini);

