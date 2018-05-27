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
__used
__attribute__((section("__versions"))) = {
	{ 0x35746b77, "module_layout" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xd29f8c93, "device_remove_file" },
	{ 0x153b1ca8, "kmalloc_caches" },
	{ 0x77cb5806, "device_destroy" },
	{ 0x930fa371, "__register_chrdev" },
	{ 0x44320cfd, "nf_register_hook" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x6fc13ba6, "__pskb_pull_tail" },
	{ 0x50eedeb8, "printk" },
	{ 0x42224298, "sscanf" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0x6c2e3320, "strncmp" },
	{ 0xb0f2df0b, "device_create" },
	{ 0x969391b7, "device_create_file" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x44b87ef7, "kmem_cache_alloc_trace" },
	{ 0x1d2e87c6, "do_gettimeofday" },
	{ 0x6e686b39, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0xf9e73082, "scnprintf" },
	{ 0xaf243a97, "class_destroy" },
	{ 0xb81960ca, "snprintf" },
	{ 0x7d50a24, "csum_partial" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0xa55d174, "__class_create" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "4BB9B306BFCF4CBEC905AE6");
