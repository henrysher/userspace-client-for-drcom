#ifndef _TCPTRACK_H_
#define _TCPTRACK_H_

#include <linux/if.h>

#define CONN_SO_BASE_CTL	(64+2048+64)

#define CONN_SO_SET_AUTH_CMD	CONN_SO_BASE_CTL
#define CONN_SO_SET_PARAMS	(CONN_SO_BASE_CTL+1)
#define CONN_SO_SET_MAX		CONN_SO_SET_PARAMS

#define CONN_MODE_NONE		0
#define CONN_MODE_AUTH 		1

#define CONN_AUTH_DATA_LEN	16

struct e_address
{
	u_int32_t	addr;
	u_int32_t	mask;
};

struct conn_param
{
	char			devname[IFNAMSIZ];

	int			e_count;
	struct e_address	es[0];
};

struct conn_auth_cmd
{
	int 		cmd;
	pid_t		pid;
	int		autologout;
	unsigned char	auth_data[CONN_AUTH_DATA_LEN];
};

#endif

