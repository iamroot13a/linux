/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>
#include <linux/psci.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/efi.h>
#include <asm/elf.h>
#include <asm/early_ioremap.h>
#include <asm/fixmap.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>
#include <asm/xen/hypervisor.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

extern void init_default_cache_policy(unsigned long);
extern void paging_init(const struct machine_desc *desc);
extern void early_paging_init(const struct machine_desc *);
extern void sanity_check_meminfo(void);
extern enum reboot_mode reboot_mode;
extern void setup_dma_zone(const struct machine_desc *desc);

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

#if 0  /* @Iamroot: 2017.02.11 */
__initdata : 메모리 한쪽에 잘 모아 놨다가
     시스템 초기화 시에 한번만 실행하고 사용이 끝나면 메모리에서 제거하는 변수
#endif /* @Iamroot  */
unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

const char *system_serial;
EXPORT_SYMBOL(system_serial);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);

unsigned int elf_hwcap2 __read_mostly;
EXPORT_SYMBOL(elf_hwcap2);


#ifdef MULTI_CPU
struct processor processor __read_mostly;
#endif
#ifdef MULTI_TLB
struct cpu_tlb_fns cpu_tlb __read_mostly;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __read_mostly;
#endif
#ifdef MULTI_CACHE
struct cpu_cache_fns cpu_cache __read_mostly;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __read_mostly;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

struct stack {
	u32 irq[3];
	u32 abt[3];
	u32 und[3];
	u32 fiq[3];
} ____cacheline_aligned;
/*@Iamroot 170203
 * r0, lr, spsr를 저장하기 위해 각 모드에 배열을 3개로 설정
 */


#ifndef CONFIG_CPU_V7M
static struct stack stacks[NR_CPUS];
#endif

char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
const struct machine_desc *machine_desc __initdata;

static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	}
};

#define video_ram   mem_res[0]
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else
/*@Iamroot 170104
 * MIDR 비교 후 [19:16]비트가 0xf이면 mmfr0를 비교해서 cpu_arch를 구한다.
 * raspberry pi2에서 cpu_arch는 9(CPU_ARCH_ARMv7)이다.
 */
static int __get_cpu_architecture(void)
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		unsigned int mmfr0 = read_cpuid_ext(CPUID_EXT_MMFR0);
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

int __pure cpu_architecture(void)
{
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	return __cpu_architecture;
}

static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	if (icache_is_pipt())
		return 0;

	/* arch specifies the register format */
	switch (arch) {
	case CPU_ARCH_ARMv7:
		asm("mcr	p15, 2, %0, c0, c0, 0 @ set CSSELR"
		    : /* No output operands */
		    : "r" (1));
#if 0  /* @Iamroot: 2017.01.21 */
1 : instruction cache
0 : data cache
cache level은 0으로 설정
manual p.1555 : CSSELR
#endif /* @Iamroot  */
		isb();
		asm("mrc	p15, 1, %0, c0, c0, 0 @ read CCSIDR"
		    : "=r" (id_reg));
		line_size = 4 << ((id_reg & 0x7) + 2);
#if 0  /* @Iamroot: 2017.01.21 */
                Log 2 (Number of words in cache line)) -2
#endif /* @Iamroot  */
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
#if 0  /* @Iamroot: 2017.01.21 */
                aliasing_icache 는 1로 간주 하고 진행
                http://lists.infradead.org/pipermail/linux-arm-kernel/2015-October/382023.html
                참고
#endif /* @Iamroot  */
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

static void __init cacheid_init(void)
{
	unsigned int arch = cpu_architecture();
#if 0  /* @Iamroot: 2017.01.21 */
        arch = 9(ARMv7)
#endif /* @Iamroot  */

	if (arch == CPU_ARCH_ARMv7M) {
		cacheid = 0;
	} else if (arch >= CPU_ARCH_ARMv6) {
		unsigned int cachetype = read_cpuid_cachetype();
		if ((cachetype & (7 << 29)) == 4 << 29) {
#if 0  /* @Iamroot: 2017.01.21 */
                    CTR의 format 과 비교 
#endif /* @Iamroot  */
			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;
#if 0  /* @Iamroot: 2017.01.21 */
                        virtaul index, physical tag
                        모기향 p.225 참고 
#endif /* @Iamroot  */
			switch (cachetype & (3 << 14)) {
#if 0  /* @Iamroot: 2017.01.21 */
                    CTR의 L1IP와 비교
#endif /* @Iamroot  */
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
#if 0  /* @Iamroot: 2017.01.21 */
                                virtual index, virtual tag
                                ASID : address space id
#endif /* @Iamroot  */
				break;
			case (3 << 14):
				cacheid |= CACHEID_PIPT;
#if 0  /* @Iamroot: 2017.01.21 */
                                physical index physical tag
#endif /* @Iamroot  */
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
		if (cpu_has_aliasing_icache(arch))
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	pr_info("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	va_list ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

#ifdef CONFIG_ARM_PATCH_IDIV

static inline u32 __attribute_const__ sdiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "sdiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfb90, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "sdiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe710f110);
}

static inline u32 __attribute_const__ udiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "udiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfbb0, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "udiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe730f110);
}

static inline u32 __attribute_const__ bx_lr_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "bx lr; nop" */
		u32 insn = __opcode_thumb32_compose(0x4770, 0x46c0);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "bx lr" */
	return __opcode_to_mem_arm(0xe12fff1e);
}

/*@Iamroot 170114
 * aeabi : ARM Embedded-Application Binary Interface
 */
static void __init patch_aeabi_idiv(void)
{
	extern void __aeabi_uidiv(void);
	extern void __aeabi_idiv(void);
	uintptr_t fn_addr;
	unsigned int mask;

	/*@Iamroot 170114
	 * mask = HWCAP_IDIVA
	 * !(elf_hwcap & mask) = 0이므로 return하지 않는다.
	 */
	mask = IS_ENABLED(CONFIG_THUMB2_KERNEL) ? HWCAP_IDIVT : HWCAP_IDIVA;
	if (!(elf_hwcap & mask))
		return;
#if 0  /* @Iamroot: 2017.01.21 */
        IS_ENABLED를 통하여 해당 명령어를 지원하는지 확인하여 지원하다면
        아래 루틴을 진행한다 
#endif /* @Iamroot  */

	pr_info("CPU: div instructions available: patching division code\n");

	/*@Iamroot 170114
	 * udiv, sdiv, "bx lr" instruction 명령어가 존재한다해도 kernel에서는 직접 만든 코드로 각각 대체한다.
	 * 이는 성능 향상을 목적으로 함
	 * flush_icache_range()는 기존 캐시에 저장되었던 기존 명령어들을 갱신하기 위해 flush함
	 */
	fn_addr = ((uintptr_t)&__aeabi_uidiv) & ~1;
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = udiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);

	fn_addr = ((uintptr_t)&__aeabi_idiv) & ~1;
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = sdiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);
}

#else
static inline void patch_aeabi_idiv(void) { }
#endif

static void __init cpuid_init_hwcaps(void)
{
	int block;
	u32 isar5;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		return;

	block = cpuid_feature_extract(CPUID_EXT_ISAR0, 24);
	/*@Iamroot 170114
	 * block이 0b10이라 가정한다.(ARM, THUMB instruction 지원)
	 */

	if (block >= 2)
		elf_hwcap |= HWCAP_IDIVA;
	if (block >= 1)
		elf_hwcap |= HWCAP_IDIVT;

	/* LPAE implies atomic ldrd/strd instructions */
	/*@Iamroot 170114
	 * LPAE 지원 여부를 확인한다.
	 * 우리는 LPAE를 지원하지 않는다고 가정함
	 */

	block = cpuid_feature_extract(CPUID_EXT_MMFR0, 0);
	if (block >= 5)
		elf_hwcap |= HWCAP_LPAE;

	/* check for supported v8 Crypto instructions */
	/*@Iamroot 170114
	 * cpuid_feature_extract_field(isar5, x)는 armv8일 때 설정된다.
	 */
	isar5 = read_cpuid_ext(CPUID_EXT_ISAR5);

	block = cpuid_feature_extract_field(isar5, 4);
	if (block >= 2)
		elf_hwcap2 |= HWCAP2_PMULL;
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_AES;

	block = cpuid_feature_extract_field(isar5, 8);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA1;

	block = cpuid_feature_extract_field(isar5, 12);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA2;

	block = cpuid_feature_extract_field(isar5, 16);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_CRC32;
}

static void __init elf_hwcap_fixup(void)
{
	unsigned id = read_cpuid_id();

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if (read_cpuid_part() == ARM_CPU_PART_ARM1136 &&
	    ((id >> 20) & 3) == 0) {
		elf_hwcap &= ~HWCAP_TLS;
		return;
	}

#if 0  /* @Iamroot: 2017.01.21 */
TLS : thread local storage
          각각의 스레드가 같은 전역, 정적 변수에 접근하더라도
          서로 다르게 독립적으로 사용할수 있게 한다
#endif /* @Iamroot  */
	/* Verify if CPUID scheme is implemented */
	if ((id & 0x000f0000) != 0x000f0000)
		return;
#if 0  /* @Iamroot: 2017.01.21 */
      MIDR에서 ARMv7 은 Architecture의 값이 F.
#endif /* @Iamroot  */

	/*
	 * If the CPU supports LDREX/STREX and LDREXB/STREXB,
	 * avoid advertising SWP; it may not be atomic with
	 * multiprocessing cores.
	 */
	if (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) > 1 ||
	    (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) == 1 &&
	     cpuid_feature_extract(CPUID_EXT_ISAR4, 20) >= 3))
		elf_hwcap &= ~HWCAP_SWP;
#if 0  /* @Iamroot: 2017.01.21 */
      cpuid_feature_extract(CPUID_EXT_ISAR3, 12) : SynchPrim_instrs
      cpuid_feature_extract(CPUID_EXT_ISAR4, 20) : SynchPrim_instrs_frac
      HWCAP_SWP : 레지스터와 메모리 값을 한번에 바꿀수 있는 기능
                  - multi core 에서는 사용하지 않음 
#endif /* @Iamroot  */
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M
	unsigned int cpu = smp_processor_id();
	struct stack *stk = &stacks[cpu];

	if (cpu >= NR_CPUS) {
		pr_crit("CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));
#if 0  /* @Iamroot: 2017.01.21 */
        per_cpu의 offset을 읽어와 자신의 cpu의 offset 설정
        banked register 를 사용
#endif /* @Iamroot  */
	cpu_proc_init();
#if 0  /* @Iamroot: 2017.01.21 */
cpu_proc_init : {return lr}
#endif /* @Iamroot  */

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL
#define PLC	"r"
#else
#define PLC	"I"
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */
	__asm__ (
	"msr	cpsr_c, %1\n\t"
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7\n\t"
	"add	r14, %0, %8\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %9"
	    :
	    : "r" (stk),
	      PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE),
	      "I" (offsetof(struct stack, irq[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | ABT_MODE),
	      "I" (offsetof(struct stack, abt[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | UND_MODE),
	      "I" (offsetof(struct stack, und[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | FIQ_MODE),
	      "I" (offsetof(struct stack, fiq[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | SVC_MODE)
	    : "r14");
	/*@Iamroot 170203
	 * %1 : "r" (stk)
	 * %2 : PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE)
	 * 요런식으로 %n에 각각 대입
	 * 자세한 어셈블리 문법은 https://goo.gl/0S7Fb0 참고
	 * IRQ, ABT, UND, FIQ, SVC 모드의 Stack Pointer를 설정
	 * 마지막에 언급된 r14 레지스터는 컴파일러가 수정하지 못하게 막아놓음
	 */

#endif
}

u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

void __init smp_setup_processor_id(void)
{
	int i;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	/*@Iamroot 161119
	 * mpidr : 멀티프로세싱 시스템에서 추가 프로세서 식별 메커니즘을 제공하고 다중 처리 확장에 포함되는지 여부를 나타낸다.(ARM reference 1651쪽 참고)
	 * mpidr = smp이면 0xFFFFFF mask하고 아니면 0
	 * cpu = mpidr[7:0]를 읽어온 값 - 현재 실행하는 cpuid
	 */

	cpu_logical_map(0) = cpu;
	for (i = 1; i < nr_cpu_ids; ++i)
		cpu_logical_map(i) = i == cpu ? 0 : i;
	/*@Iamroot 161119
	 * cpu_logical_map() : CPU Core의 논리 번호를 지정
	 */

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 */
	/*@Iamroot 161119
	 * percpu : cpu별로 데이터를 생성하고 관리할 수 있는 인터페이스
	 * set_my_cpu_offset() : percpu를 사용하기 위해 per_cpu offset를 TPIDRPRW에 저장
	 * TPIDRPRW : ARM reference 1722쪽 참고
	 *pr_info() = fprintf(stderr, args);
	 */

	set_my_cpu_offset(0);

	pr_info("Booting Linux on physical CPU 0x%x\n", mpidr);
}
#if 0  /* @Iamroot: 2019.06.29 */
mpidr_hash : cpu id정보와 mpidr정보를 가져와 hash테이블 생성. 
-> CPU ID값을 키값으로 해서 MPDIR_hashtable을 통해 빠르게 affinity레벨의 CPU ID를 구해옴
-> shift 값을 구해놓음으로써 CPU ID값을 빠르게 가져올수 있음
링크 : http://jake.dothome.co.kr/smp_build_mpidr_hash/

********************************
해쉬테이블 생성 예시

fls() 계산 : x = 0x3 & 0xffff0000 -> x = 0x30000, 
X << 16 -> r = 16 // x = 0x30000 00 -> r =8 // x = 0x30000 00 0 ->  r=4 //
x = 0xC0000 00 0 -> r = 2 //  return 2 -> 위치 2번째

*************************************
ffs () 계산 : x = 0x3 & 0xffff -> return 1

*************************************
aff[] 계산 : ls = 2, fs[0] = 0, bits[0] = 2
aff[0] = 0 // aff[1] = 6 // aff[2] = 14

mask = 3, bits = 2

*************************************

sync_cache_w()
->hash 구조체 주소정보를 가져와 사이즈 구하고 datacache 할당 및 flush
->outer cache 또한 할당 및 clean

#endif /* @Iamroot  */


struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	pr_debug("mask of set bits 0x%x\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		bits[i] = ls - fs[i];
	}
	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
	mpidr_hash.mask = mask;
	mpidr_hash.bits = bits[2] + bits[1] + bits[0];
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
}
#endif

static void __init setup_processor(void)
{
	struct proc_info_list *list;

	/*
	 * locate processor in the list of supported processor
	 * types.  The linker builds this table for us from the
	 * entries in arch/arm/mm/proc-*.S
	 */
	/*@Iamroot 170114
	 * __lookup_processor_type에서 반환한 processor_type 구조체를 list에 넣는다
	 * raspberry pi2에서는 __v7_ca7mp_proc_info 구조체가 list에 들어간다.
	 */
	list = lookup_processor_type(read_cpuid_id());
	if (!list) {
		pr_err("CPU configuration botched (ID %08x), unable to continue.\n",
		       read_cpuid_id());
		while (1);
	}

	cpu_name = list->cpu_name;
	__cpu_architecture = __get_cpu_architecture();
	/*@Iamroot 170114
	 * __cpu_architecture = 9
	 */
	
	/*@Iamroot 170114
	 * raspberry pi2에서는 MULTI_CPU가 set되어 있다.(CONFIG_CPU_V7)
	 */
#ifdef MULTI_CPU
	processor = *list->proc;
#endif
#ifdef MULTI_TLB
	cpu_tlb = *list->tlb;
#endif
#ifdef MULTI_USER
	cpu_user = *list->user;
#endif
#ifdef MULTI_CACHE
	cpu_cache = *list->cache;
#endif

	pr_info("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
		cpu_name, read_cpuid_id(), read_cpuid_id() & 15,
		proc_arch[cpu_architecture()], get_cr());

	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	/*@Iamroot 170114
	 * kernel 버전과 cpu 정보, 버전과 Endian을 init_utsname에 넣는다.
	 * ex) Linux odroid 4.2.0-rc1+ #4 SMP PREEMPT Fri Jul 10 16:45:24 KST 2015 armv7l
	 * uts : unix timesharing system의 약자
	 */

	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	elf_hwcap = list->elf_hwcap;

	cpuid_init_hwcaps();
	patch_aeabi_idiv();


#ifndef CONFIG_ARM_THUMB
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT);
#endif
#ifdef CONFIG_MMU
	init_default_cache_policy(list->__cpu_mm_mmu_flags);
#if 0  /* @Iamroot: 2017.01.21 */
__cpu_mm_mmu_flags :
	ALT_SMP(.long	PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | \
			PMD_SECT_AF | PMD_FLAGS_SMP | \mm_mmuflags)
#endif /* @Iamroot  */
#endif
	erratum_a15_798181_init();

	elf_hwcap_fixup();

	cacheid_init();
	cpu_init();
}

void __init dump_machine_table(void)
{
	const struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

int __init arm_add_memory(u64 start, u64 size)
{
	u64 aligned_start;

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is rounded down, start is rounded up.
	 */

#if 0  /* @Iamroot: 2017.03.18 */
		* start address는 page size만큼 round-up하고 size는 round-up 된 것만큼 줄여준다 
#endif /* @Iamroot  */
	aligned_start = PAGE_ALIGN(start);
	if (aligned_start > start + size)
		size = 0;
	else
		size -= aligned_start - start;


#ifndef CONFIG_ARCH_PHYS_ADDR_T_64BIT
#if 0  /* @Iamroot: 2017.03.18 */
		* aligned_start가 32bit가 허용하는 최대값을 넘어가는지 체크 
#endif /* @Iamroot  */
	if (aligned_start > ULONG_MAX) {
		pr_crit("Ignoring memory at 0x%08llx outside 32-bit physical address space\n",
			(long long)start);
		return -EINVAL;
	}

#if 0  /* @Iamroot: 2017.03.18 */
		* aligned_start부터 최대 size까지 쓰겠다.
#endif /* @Iamroot  */
	if (aligned_start + size > ULONG_MAX) {
		pr_crit("Truncating memory at 0x%08llx to fit in 32-bit physical address space\n",
			(long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		size = ULONG_MAX - aligned_start;
	}
#endif

#if 0  /* @Iamroot: 2017.03.18 */
		* aligned_start + size 가 PHYS_OFFSET보다 작으면 사용할 공간이 없어서 사용불가 
		* aligned_start가 PHYS_OFFSET보다 작지만 size를 더했을 경우 PHYS_OFFSET보다 클 경우
		* PHYS_OFFSET부터 aligned_start + size 까지 사용한다.
#endif /* @Iamroot  */
	if (aligned_start < PHYS_OFFSET) {
		if (aligned_start + size <= PHYS_OFFSET) {
			pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
				aligned_start, aligned_start + size);
			return -EINVAL;
		}

		pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
			aligned_start, (u64)PHYS_OFFSET);

		size -= PHYS_OFFSET - aligned_start;
		aligned_start = PHYS_OFFSET;
	}

	start = aligned_start;

#if 0  /* @Iamroot: 2017.03.18 */
		* size를 round-down
#endif /* @Iamroot  */
	size = size & ~(phys_addr_t)(PAGE_SIZE - 1);

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (size == 0)
		return -EINVAL;

	memblock_add(start, size);
	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */

static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	u64 size;
	u64 start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	
#if 0  /* @Iamroot: 2017.03.18 */
		* 논리적으로 할당된 memblock을 전부 삭제한다. 
#endif /* @Iamroot  */
	if (usermem == 0) {
		usermem = 1;
		memblock_remove(memblock_start_of_DRAM(),
			memblock_end_of_DRAM() - memblock_start_of_DRAM());
	}

#if 0  /* @Iamroot: 2017.03.18 */
		* CONFIG_PHYS_OFFSET은 컴파일을 해야 생성되는 define이고 뜻은 커널이 가질수 있는 물리메모리			* 의 시작주소 
		* mem= 64m@0x80000000 경우 전체 메모리가 64Mb 시작주소는 0x80000000
		* '@'이후부터는 생략가능 
#endif /* @Iamroot  */
	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

#if 0  /* @Iamroot: 2018.06.09 */
    request_standard_resources :   플랫폼에  의존적이지  않고 공통적으로  관리되는  리소스  정보를
	트리 형태로 구성

    *System Ram 영역에 kernel code, data 영역 추가
    *mdesc(machine description)에 Video 정보 존재시 비디오 램영역  추가
	*LP0(Line Printer port),lp1,lp2 영역 추가

	*System Ram 영역 구성시 - for_each_memblock()
	-> 구조체 배열 리소스 사이즈 만큼 Memblock의 할당 받아 memblock 시작/끝 주소 기록

	*request_resource(&iomem_resource,res) : 전역 iomem_resource에 System Ram영역(memblock 영역)에 
	대한 리소스를 등록
	
	* 커널코드/데이터의 물리주소(영역)가 System Ram 물리주소(영역)에 포함된 경우 System Ram의 Child
	에 추가(리소스 등록)
	-> 추후 이 부분은 UnWrite의 하기위함인듯(?) 

    request_resource() 는 문C 블로그내 설명을 참고할것
	http://jake.dothome.co.kr/tcm_init/

	request_resource 함수에 대해 간략히 설명하자면, 
	request_resource_conflict 함수 :  write_lock/unlock을 통해 동기화 제어한 상태에서
	리소스 관리 -> new 리소스가 root 범위와 겹치지 않을경우 sibling에 추가함

#endif /* @Iamroot  */

static void __init request_standard_resources(const struct machine_desc *mdesc)
{
	struct memblock_region *region;
	struct resource *res;

	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(_etext - 1);
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);

	for_each_memblock(memory, region) {
		res = memblock_virt_alloc(sizeof(*res), 0);
		res->name  = "System RAM";
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;
		res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;

		request_resource(&iomem_resource, res);

		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
	}

	if (mdesc->video_start) {
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	if (mdesc->reserve_lp0)
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE) || \
    defined(CONFIG_EFI)
struct screen_info screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	of_iommu_init();
	if (machine_desc->init_machine)
		machine_desc->init_machine();
#ifdef CONFIG_OF
	else
		of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
#endif
	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	struct device_node *root;
	int ret;

	if (machine_desc->init_late)
		machine_desc->init_late();

	root = of_find_node_by_path("/");
	if (root) {
		ret = of_property_read_string(root, "serial-number",
					      &system_serial);
		if (ret)
			system_serial = NULL;
	}

	if (!system_serial)
		system_serial = kasprintf(GFP_KERNEL, "%08x%08x",
					  system_serial_high,
					  system_serial_low);

	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_KEXEC
/*
 * The crash region must be aligned to 128MB to avoid
 * zImage relocating below the reserved region.
 */
#define CRASH_ALIGN	(128 << 20)

static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base);
	if (ret)
		return;

	if (crash_base <= 0) {
		unsigned long long crash_max = idmap_to_phys((u32)~0);
		crash_base = memblock_find_in_range(CRASH_ALIGN, crash_max,
						    crash_size, CRASH_ALIGN);
		if (!crash_base) {
			pr_err("crashkernel reservation failed - No suitable area found.\n");
			return;
		}
	} else {
		unsigned long long start;

		start = memblock_find_in_range(crash_base,
					       crash_base + crash_size,
					       crash_size, SECTION_SIZE);
		if (start != crash_base) {
			pr_err("crashkernel reservation failed - memory is in use.\n");
			return;
		}
	}

	ret = memblock_reserve(crash_base, crash_size);
	if (ret < 0) {
		pr_warn("crashkernel reservation failed - memory is in use (0x%lx)\n",
			(unsigned long)crash_base);
		return;
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_KEXEC */

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc;

	setup_processor();
#if 0  /* @Iamroot: 2017.02.11 */
__atags_pointer : kernel/head-common.S에 선언되어있는 변수 그대로 사용 
#endif /* @Iamroot  */
	mdesc = setup_machine_fdt(__atags_pointer);
	if (!mdesc)
		mdesc = setup_machine_tags(__atags_pointer, __machine_arch_type);
	machine_desc = mdesc;
	machine_name = mdesc->name;
	dump_stack_set_arch_desc("%s", mdesc->name);

	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;

	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;

	/* populate cmd_line too for later use, preserving boot_command_line */
	/*@Iamroot 170311
	 * setup_machine_fdt에 설정된 boot_command_line를 cmd_line에 넣는다.
	 */
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = cmd_line;

	early_fixmap_init();
	early_ioremap_init();

	parse_early_param();

#ifdef CONFIG_MMU
	early_paging_init(mdesc);
#endif
	setup_dma_zone(mdesc);

#if 0  /* @Iamroot: 2017.03.18 */
		* efi_init()은 지원안하므로 패스
#endif /* @Iamroot  */
	efi_init();
	sanity_check_meminfo();
	arm_memblock_init(mdesc);

	early_ioremap_reset();

	paging_init(mdesc);
	request_standard_resources(mdesc);
#if 0  /* @Iamroot: 2018.06.09 */
    multi CPU인경우 arm_pm_restart 적용되어야 함
	-> Rasberry Pi2의 경우 1 CPU이기 때문에 mdesc에 기입 X 로 생각됨
#endif /* @Iamroot  */

	if (mdesc->restart)
		arm_pm_restart = mdesc->restart;

	unflatten_device_tree();

	arm_dt_init_cpu_maps();
	psci_dt_init();
#if 0  /* @Iamroot: 2019.06.29 */
xen_early_init() : xen hypervisor 지원버전및 feature 지원여부 확인.
                   user-set 되어있는것이 없을 경우 'hvc' preferred colsole로 세팅함	

smp_init_cpus() : device possible cpu수 정보 가져오고, 해당 cpu 코어번호에 대해 cpu possible 비트설정

smp_ops 전역변수설정 : smp 오퍼레이션은 크게 3가지 타입으로 나뉜다
1. mdesc를 사용하는 smp operation, 2.PSCI용 3.Spin-table을 사용(ARM64용 ? )

#endif /* @Iamroot  */
	xen_early_init();
#ifdef CONFIG_SMP
	if (is_smp()) {
		if (!mdesc->smp_init || !mdesc->smp_init()) {
			if (psci_smp_available())
				smp_set_ops(&psci_smp_ops);
			else if (mdesc->smp)
				smp_set_ops(mdesc->smp);
		}
		smp_init_cpus();
		smp_build_mpidr_hash();
	}
#endif

	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel();

#ifdef CONFIG_MULTI_IRQ_HANDLER
	handle_arch_irq = mdesc->handle_irq;
#endif

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif

	if (mdesc->init_early)
		mdesc->init_early();
}


static int __init topology_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm *cpuinfo = &per_cpu(cpu_data, cpu);
		cpuinfo->cpu.hotpluggable = platform_can_hotplug_cpu(cpu);
		register_cpu(&cpuinfo->cpu, cpu);
	}

	return 0;
}
subsys_initcall(topology_init);

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	NULL
};

static const char *hwcap2_str[] = {
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

#if defined(CONFIG_SMP)
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   per_cpu(cpu_data, i).loops_per_jiffy / (500000UL/HZ),
			   (per_cpu(cpu_data, i).loops_per_jiffy / (5000UL/HZ)) % 100);
#else
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000/HZ),
			   (loops_per_jiffy / (5000/HZ)) % 100);
#endif
		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		for (j = 0; hwcap2_str[j]; j++)
			if (elf_hwcap2 & (1 << j))
				seq_printf(m, "%s ", hwcap2_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %s\n", system_serial);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};
