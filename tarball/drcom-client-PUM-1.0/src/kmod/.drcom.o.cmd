cmd_/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.o := gcc -m32 -Wp,-MD,/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/.drcom.o.d  -nostdinc -isystem /usr/lib/gcc/i486-linux-gnu/4.2.4/include -D__KERNEL__  -Iinclude  -include include/linux/autoconf.h -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -O2 -pipe -msoft-float -mregparm=3 -freg-struct-return -mpreferred-stack-boundary=2  -march=i586 -mtune=generic -ffreestanding -maccumulate-outgoing-args   -Iinclude/asm-x86/mach-default -fomit-frame-pointer -g  -fno-stack-protector -Wdeclaration-after-statement -Wno-pointer-sign  -I/include  -DMODULE -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(drcom)"  -D"KBUILD_MODNAME=KBUILD_STR(drcom)" -c -o /home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/.tmp_drcom.o /home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.c

deps_/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.o := \
  /home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.c \
  include/linux/version.h \
  include/linux/module.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/markers.h) \
    $(wildcard include/config/sysfs.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc4.h \
    $(wildcard include/config/forced/inlining.h) \
  include/linux/compiler-gcc.h \
  include/linux/poison.h \
  include/linux/prefetch.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbd.h) \
    $(wildcard include/config/lsf.h) \
    $(wildcard include/config/resources/64bit.h) \
  include/linux/posix_types.h \
  include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  include/asm/posix_types_32.h \
  include/asm/types.h \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/highmem64g.h) \
  include/asm/processor.h \
  include/asm/processor_32.h \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/x86/ht.h) \
    $(wildcard include/config/paravirt.h) \
  include/asm/vm86.h \
    $(wildcard include/config/vm86.h) \
  include/asm/ptrace.h \
  include/asm/ptrace-abi.h \
  include/asm/segment.h \
  include/asm/segment_32.h \
  include/asm/math_emu.h \
  include/asm/sigcontext.h \
  include/asm/page.h \
  include/asm/page_32.h \
    $(wildcard include/config/x86/use/3dnow.h) \
    $(wildcard include/config/x86/pae.h) \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/highmem4g.h) \
    $(wildcard include/config/page/offset.h) \
    $(wildcard include/config/flatmem.h) \
  include/asm-generic/pgtable-nopmd.h \
  include/asm-generic/pgtable-nopud.h \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
    $(wildcard include/config/sparsemem.h) \
    $(wildcard include/config/out/of/line/pfn/to/page.h) \
  include/asm-generic/page.h \
  include/asm/cpufeature.h \
  include/asm/cpufeature_32.h \
  include/linux/bitops.h \
  include/asm/bitops.h \
  include/asm/bitops_32.h \
  include/asm/alternative.h \
  include/asm/alternative_32.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/ext2-non-atomic.h \
  include/asm-generic/bitops/le.h \
  include/asm/byteorder.h \
    $(wildcard include/config/x86/bswap.h) \
  include/linux/byteorder/little_endian.h \
  include/linux/byteorder/swab.h \
  include/linux/byteorder/generic.h \
  include/asm-generic/bitops/minix.h \
  include/asm/required-features.h \
    $(wildcard include/config/x86/minimum/cpu/family.h) \
    $(wildcard include/config/math/emulation.h) \
    $(wildcard include/config/x86/cmov.h) \
  include/asm/msr.h \
  include/asm/msr-index.h \
  include/asm/errno.h \
  include/asm-generic/errno.h \
  include/asm-generic/errno-base.h \
  include/asm/system.h \
  include/asm/system_32.h \
    $(wildcard include/config/x86/ppro/fence.h) \
    $(wildcard include/config/x86/oostore.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/printk.h) \
    $(wildcard include/config/numa.h) \
  /usr/lib/gcc/i486-linux-gnu/4.2.4/include/stdarg.h \
  include/linux/linkage.h \
  include/asm/linkage.h \
  include/asm/linkage_32.h \
    $(wildcard include/config/x86/alignment/16.h) \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/asm/bug.h \
    $(wildcard include/config/bug.h) \
    $(wildcard include/config/debug/bugverbose.h) \
  include/asm-generic/bug.h \
  include/asm/div64.h \
  include/asm/cmpxchg.h \
  include/asm/cmpxchg_32.h \
    $(wildcard include/config/x86/cmpxchg.h) \
  include/asm/nops.h \
  include/asm/nops_32.h \
    $(wildcard include/config/mk8.h) \
    $(wildcard include/config/mk7.h) \
    $(wildcard include/config/m686.h) \
    $(wildcard include/config/mpentiumii.h) \
    $(wildcard include/config/mpentiumiii.h) \
    $(wildcard include/config/mpentiumm.h) \
    $(wildcard include/config/mcore2.h) \
    $(wildcard include/config/pentium4.h) \
    $(wildcard include/config/x86/generic.h) \
  include/asm/paravirt.h \
    $(wildcard include/config/x86/local/apic.h) \
    $(wildcard include/config/highpte.h) \
  include/linux/cpumask.h \
    $(wildcard include/config/hotplug/cpu.h) \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
  include/asm/string.h \
  include/asm/string_32.h \
  include/asm/kmap_types.h \
    $(wildcard include/config/debug/highmem.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
    $(wildcard include/config/x86.h) \
  include/asm/irqflags.h \
  include/asm/irqflags_32.h \
    $(wildcard include/config/debug/lock/alloc.h) \
  include/asm/processor-flags.h \
  include/linux/cache.h \
  include/asm/cache.h \
    $(wildcard include/config/x86/l1/cache/shift.h) \
    $(wildcard include/config/x86/vsmp.h) \
  include/asm/percpu.h \
  include/asm/percpu_32.h \
  include/linux/init.h \
    $(wildcard include/config/hotplug.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/acpi/hotplug/memory.h) \
  include/linux/stat.h \
  include/asm/stat.h \
  include/linux/time.h \
  include/linux/seqlock.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/preempt.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
  include/asm/thread_info.h \
  include/asm/thread_info_32.h \
    $(wildcard include/config/4kstacks.h) \
    $(wildcard include/config/debug/stack/usage.h) \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  include/asm/spinlock_types.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/generic/hardirqs.h) \
    $(wildcard include/config/prove/locking.h) \
  include/asm/spinlock.h \
  include/asm/spinlock_32.h \
  include/asm/atomic.h \
  include/asm/atomic_32.h \
    $(wildcard include/config/m386.h) \
  include/asm-generic/atomic.h \
  include/asm/rwlock.h \
  include/linux/spinlock_api_smp.h \
  include/linux/kmod.h \
    $(wildcard include/config/kmod.h) \
  include/linux/errno.h \
  include/linux/elf.h \
  include/linux/elf-em.h \
  include/asm/elf.h \
  include/asm/user.h \
  include/asm/user_32.h \
  include/asm/auxvec.h \
  include/asm/desc.h \
  include/asm/desc_32.h \
  include/asm/ldt.h \
  include/linux/smp.h \
  include/asm/smp.h \
  include/asm/smp_32.h \
    $(wildcard include/config/x86/io/apic.h) \
  include/asm/mpspec.h \
  include/asm/mpspec_32.h \
    $(wildcard include/config/acpi.h) \
  include/asm/mpspec_def.h \
  include/asm-x86/mach-default/mach_mpspec.h \
  include/asm/apic.h \
  include/asm/apic_32.h \
    $(wildcard include/config/x86/good/apic.h) \
  include/linux/pm.h \
    $(wildcard include/config/pm/sleep.h) \
  include/linux/delay.h \
  include/asm/delay.h \
  include/asm/fixmap.h \
  include/asm/fixmap_32.h \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/x86/visws/apic.h) \
    $(wildcard include/config/x86/f00f/bug.h) \
    $(wildcard include/config/x86/cyclone/timer.h) \
    $(wildcard include/config/pci/mmconfig.h) \
  include/asm/acpi.h \
  include/asm/acpi_32.h \
  include/acpi/pdc_intel.h \
  include/asm/apicdef.h \
  include/asm/apicdef_32.h \
  include/asm/io_apic.h \
  include/asm/io_apic_32.h \
  include/asm-x86/mach-default/mach_apicdef.h \
  include/linux/percpu.h \
  include/linux/slab.h \
    $(wildcard include/config/slab/debug.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
    $(wildcard include/config/slabinfo.h) \
  include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/arch/populates/node/map.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
    $(wildcard include/config/holes/in/zone.h) \
  include/linux/wait.h \
  include/asm/current.h \
  include/asm/current_32.h \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/nodemask.h \
  include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
  include/linux/notifier.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/asm/rwsem.h \
  include/linux/srcu.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
  include/asm/topology.h \
  include/asm/topology_32.h \
  include/asm-generic/topology.h \
  include/linux/slub_def.h \
    $(wildcard include/config/slub/debug.h) \
  include/linux/workqueue.h \
  include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/jiffies.h \
  include/linux/calc64.h \
  include/linux/timex.h \
    $(wildcard include/config/no/hz.h) \
  include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/asm/timex.h \
    $(wildcard include/config/x86/elan.h) \
  include/asm/tsc.h \
    $(wildcard include/config/x86/tsc.h) \
  include/linux/kobject.h \
  include/linux/sysfs.h \
  include/linux/kref.h \
  include/asm/mmu.h \
  include/linux/moduleparam.h \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/ppc64.h) \
  include/linux/marker.h \
  include/asm/local.h \
  include/asm/local_32.h \
  include/asm/module.h \
  include/asm/module_32.h \
    $(wildcard include/config/m486.h) \
    $(wildcard include/config/m586.h) \
    $(wildcard include/config/m586tsc.h) \
    $(wildcard include/config/m586mmx.h) \
    $(wildcard include/config/mpentium4.h) \
    $(wildcard include/config/mk6.h) \
    $(wildcard include/config/mcrusoe.h) \
    $(wildcard include/config/mefficeon.h) \
    $(wildcard include/config/mwinchipc6.h) \
    $(wildcard include/config/mwinchip2.h) \
    $(wildcard include/config/mwinchip3d.h) \
    $(wildcard include/config/mcyrixiii.h) \
    $(wildcard include/config/mviac3/2.h) \
    $(wildcard include/config/mviac7.h) \
    $(wildcard include/config/mgeodegx1.h) \
    $(wildcard include/config/mgeode/lx.h) \
  include/linux/sched.h \
    $(wildcard include/config/sched/debug.h) \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/audit.h) \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/posix/mqueue.h) \
    $(wildcard include/config/fair/user/sched.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/fair/group/sched.h) \
    $(wildcard include/config/blk/dev/io/trace.h) \
    $(wildcard include/config/cc/stackprotector.h) \
    $(wildcard include/config/sysvipc.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/cgroups.h) \
    $(wildcard include/config/futex.h) \
    $(wildcard include/config/compat.h) \
    $(wildcard include/config/fault/injection.h) \
    $(wildcard include/config/latencytop.h) \
  include/linux/capability.h \
  include/linux/rbtree.h \
  include/linux/mm_types.h \
    $(wildcard include/config/mmu.h) \
  include/linux/auxvec.h \
  include/linux/prio_tree.h \
  include/linux/completion.h \
  include/asm/semaphore.h \
  include/asm/semaphore_32.h \
  include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
  include/linux/ipc.h \
  include/asm/ipcbuf.h \
  include/asm/sembuf.h \
  include/linux/signal.h \
  include/asm/signal.h \
  include/asm-generic/signal.h \
  include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/securebits.h \
  include/linux/fs_struct.h \
  include/linux/pid.h \
  include/linux/rcupdate.h \
  include/linux/proportions.h \
  include/linux/percpu_counter.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/asm/seccomp.h \
  include/asm/seccomp_32.h \
  include/linux/unistd.h \
  include/asm/unistd.h \
  include/asm/unistd_32.h \
  include/linux/futex.h \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/param.h \
  include/linux/resource.h \
  include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/hrtimer.h \
    $(wildcard include/config/high/res/timers.h) \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/latencytop.h \
  include/linux/aio.h \
  include/linux/aio_abi.h \
  include/linux/uio.h \
  include/linux/netdevice.h \
    $(wildcard include/config/ax25.h) \
    $(wildcard include/config/tr.h) \
    $(wildcard include/config/net/ipip.h) \
    $(wildcard include/config/net/ipgre.h) \
    $(wildcard include/config/ipv6/sit.h) \
    $(wildcard include/config/ipv6/tunnel.h) \
    $(wildcard include/config/netpoll.h) \
    $(wildcard include/config/wireless/ext.h) \
    $(wildcard include/config/net/poll/controller.h) \
    $(wildcard include/config/netpoll/trap.h) \
    $(wildcard include/config/net/dma.h) \
    $(wildcard include/config/netdevices/multiqueue.h) \
    $(wildcard include/config/proc/fs.h) \
  include/linux/if.h \
  include/linux/socket.h \
  include/asm/socket.h \
  include/asm/sockios.h \
  include/linux/sockios.h \
  include/linux/hdlc/ioctl.h \
  include/linux/if_ether.h \
    $(wildcard include/config/sysctl.h) \
  include/linux/skbuff.h \
    $(wildcard include/config/nf/conntrack.h) \
    $(wildcard include/config/bridge/netfilter.h) \
    $(wildcard include/config/vlan/8021q.h) \
    $(wildcard include/config/net/sched.h) \
    $(wildcard include/config/net/cls/act.h) \
    $(wildcard include/config/network/secmark.h) \
  include/linux/net.h \
  include/linux/random.h \
  include/linux/ioctl.h \
  include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/sysctl.h \
  include/linux/textsearch.h \
  include/linux/err.h \
  include/net/checksum.h \
  include/asm/uaccess.h \
  include/asm/uaccess_32.h \
    $(wildcard include/config/x86/intel/usercopy.h) \
    $(wildcard include/config/x86/wp/works/ok.h) \
  include/asm/checksum.h \
  include/asm/checksum_32.h \
  include/linux/in6.h \
  include/linux/dmaengine.h \
  include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
  include/linux/ioport.h \
  include/linux/klist.h \
  include/asm/device.h \
    $(wildcard include/config/dmar.h) \
  include/linux/dma-mapping.h \
    $(wildcard include/config/has/dma.h) \
  include/asm/dma-mapping.h \
  include/asm/dma-mapping_32.h \
  include/linux/mm.h \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/debug/vm.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/debug/pagealloc.h) \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/security.h \
    $(wildcard include/config/security/network.h) \
    $(wildcard include/config/security/network/xfrm.h) \
  include/linux/fs.h \
    $(wildcard include/config/dnotify.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
    $(wildcard include/config/profiling.h) \
  include/linux/namei.h \
  include/linux/radix-tree.h \
  include/linux/quota.h \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/fcntl.h \
  include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
    $(wildcard include/config/64bit.h) \
  include/linux/binfmts.h \
  include/linux/shm.h \
  include/asm/shmparam.h \
  include/asm/shmbuf.h \
  include/linux/msg.h \
  include/asm/msgbuf.h \
  include/linux/key.h \
  include/linux/xfrm.h \
  include/net/flow.h \
  include/asm/pgtable.h \
  include/asm/pgtable_32.h \
  include/asm/pgtable-2level-defs.h \
  include/asm/pgtable-2level.h \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/s390.h) \
    $(wildcard include/config/swap.h) \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
  include/linux/scatterlist.h \
    $(wildcard include/config/debug/sg.h) \
  include/asm/scatterlist.h \
  include/asm/scatterlist_32.h \
  include/asm/io.h \
  include/asm/io_32.h \
    $(wildcard include/config/x86/numaq.h) \
  include/asm-generic/iomap.h \
  include/linux/vmalloc.h \
  include/linux/if_packet.h \
  include/net/net_namespace.h \
    $(wildcard include/config/net.h) \
    $(wildcard include/config/net/ns.h) \
  include/linux/interrupt.h \
    $(wildcard include/config/generic/irq/probe.h) \
  include/linux/irqreturn.h \
  include/linux/hardirq.h \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/smp_lock.h \
    $(wildcard include/config/lock/kernel.h) \
  include/asm/hardirq.h \
  include/asm/hardirq_32.h \
  include/linux/irq.h \
    $(wildcard include/config/irq/per/cpu.h) \
    $(wildcard include/config/irq/release/method.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/irqbalance.h) \
    $(wildcard include/config/auto/irq/affinity.h) \
    $(wildcard include/config/generic/hardirqs/no//do/irq.h) \
  include/asm/irq.h \
  include/asm/irq_32.h \
  include/asm-x86/mach-default/irq_vectors.h \
  include/asm-x86/mach-default/irq_vectors_limits.h \
  include/asm/irq_regs.h \
  include/asm/irq_regs_32.h \
  include/asm/hw_irq.h \
  include/asm/hw_irq_32.h \
  include/linux/profile.h \
  include/asm/sections.h \
  include/asm-generic/sections.h \
  include/linux/irq_cpustat.h \
  include/linux/ip.h \
  include/linux/udp.h \
  include/net/inet_sock.h \
    $(wildcard include/config/ipv6.h) \
  include/linux/jhash.h \
  include/net/sock.h \
  include/linux/filter.h \
  include/net/dst.h \
    $(wildcard include/config/net/cls/route.h) \
    $(wildcard include/config/xfrm.h) \
  include/linux/rtnetlink.h \
  include/linux/netlink.h \
  include/linux/if_link.h \
  include/linux/if_addr.h \
  include/linux/neighbour.h \
  include/net/neighbour.h \
  include/linux/seq_file.h \
  include/net/rtnetlink.h \
  include/net/netlink.h \
  include/net/request_sock.h \
  include/net/route.h \
  include/net/inetpeer.h \
  include/linux/in_route.h \
  include/linux/route.h \
  include/linux/tcp.h \
    $(wildcard include/config/tcp/md5sig.h) \
  include/net/inet_connection_sock.h \
  include/linux/poll.h \
  include/asm/poll.h \
  include/asm-generic/poll.h \
  include/net/inet_timewait_sock.h \
  include/net/tcp_states.h \
  include/net/timewait_sock.h \
  include/net/ip.h \
    $(wildcard include/config/inet.h) \
  include/linux/in.h \
  include/net/snmp.h \
  include/linux/snmp.h \
  include/linux/ipv6.h \
    $(wildcard include/config/ipv6/privacy.h) \
    $(wildcard include/config/ipv6/router/pref.h) \
    $(wildcard include/config/ipv6/route/info.h) \
    $(wildcard include/config/ipv6/optimistic/dad.h) \
    $(wildcard include/config/ipv6/mip6.h) \
    $(wildcard include/config/ipv6/subtrees.h) \
  include/linux/icmpv6.h \
  include/net/tcp.h \
  include/linux/crypto.h \
    $(wildcard include/config/crypto.h) \
  include/linux/uaccess.h \
  include/net/inet_hashtables.h \
  include/net/inet_ecn.h \
  include/net/dsfield.h \
  include/linux/netfilter.h \
    $(wildcard include/config/netfilter.h) \
    $(wildcard include/config/netfilter/debug.h) \
    $(wildcard include/config/ip/nf/nat/needed.h) \
    $(wildcard include/config/nf/nat/needed.h) \
  include/linux/proc_fs.h \
    $(wildcard include/config/proc/devicetree.h) \
    $(wildcard include/config/proc/kcore.h) \
  include/linux/magic.h \
  include/linux/netfilter_ipv4.h \
  /home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/daemon_kernel.h \

/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.o: $(deps_/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.o)

$(deps_/home/henry/repo/userspace-client-for-drcom/tarball/drcom-client-PUM-1.0/src/kmod/drcom.o):
