#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0xc697cc8c, "struct_module" },
	{ 0xb25b7293, "nf_register_sockopt" },
	{ 0x4a2ccd0c, "nf_register_hook" },
	{ 0xb869c99d, "dev_get_by_name" },
	{ 0x787880e5, "init_net" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd6c963c, "copy_from_user" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0xa0adc654, "nf_unregister_sockopt" },
	{ 0x4292364c, "schedule" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0xf2252f4, "nf_unregister_hook" },
	{ 0x19bf49a8, "skb_over_panic" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0x1b7d4074, "printk" },
	{ 0xaf4878b9, "skb_under_panic" },
	{ 0x36b841f8, "skb_copy" },
	{ 0xcbf56831, "__ip_select_ident" },
	{ 0x2124474, "ip_send_check" },
	{ 0x7d50a24, "csum_partial" },
	{ 0xd0daf136, "kfree_skb" },
	{ 0xd64c1d4b, "skb_copy_expand" },
	{ 0xa07cd914, "nf_proto_csum_replace4" },
	{ 0xe64a4b2f, "skb_make_writable" },
	{ 0x83e84bbe, "__mod_timer" },
	{ 0x98b1f5e8, "del_timer" },
	{ 0x679a54f2, "init_timer" },
	{ 0xbfffdcf6, "kmem_cache_alloc" },
	{ 0xea28d683, "kmalloc_caches" },
	{ 0xf8c59042, "skb_copy_bits" },
	{ 0xa1c9f3d, "mod_timer" },
	{ 0x7d11c268, "jiffies" },
	{ 0x88640159, "_read_unlock_bh" },
	{ 0x932da67e, "kill_proc" },
	{ 0x2462292, "_read_lock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0xd6875fa3, "_write_unlock_bh" },
	{ 0x7d278df7, "_write_lock_bh" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "9EA8ACD3EFCE4B34EBF3D97");
