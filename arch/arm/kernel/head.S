/*
 *  linux/arch/arm/kernel/head.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Kernel startup code for all 32-bit CPUs
 */
#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>
#include <asm/cp15.h>
#include <asm/domain.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/memory.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>

#if defined(CONFIG_DEBUG_LL) && !defined(CONFIG_DEBUG_SEMIHOSTING)
#include CONFIG_DEBUG_LL_INCLUDE
#endif

/*
 * swapper_pg_dir is the virtual address of the initial page table.
 * We place the page tables 16K below KERNEL_RAM_VADDR.  Therefore, we must
 * make sure that KERNEL_RAM_VADDR is correctly set.  Currently, we expect
 * the least significant 16 bits to be 0x8000, but we could probably
 * relax this restriction to KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000.
 */
#define KERNEL_RAM_VADDR	(PAGE_OFFSET + TEXT_OFFSET)
#if (KERNEL_RAM_VADDR & 0xffff) != 0x8000
#error KERNEL_RAM_VADDR must start at 0xXXXX8000
#endif

#ifdef CONFIG_ARM_LPAE
	/* LPAE requires an additional page for the PGD */
#define PG_DIR_SIZE	0x5000
#define PMD_ORDER	3
#else
#define PG_DIR_SIZE	0x4000
#define PMD_ORDER	2
#endif

	.globl	swapper_pg_dir
	.equ	swapper_pg_dir, KERNEL_RAM_VADDR - PG_DIR_SIZE

	.macro	pgtbl, rd, phys
	add	\rd, \phys, #TEXT_OFFSET
	sub	\rd, \rd, #PG_DIR_SIZE
	.endm
        /*** @Iamroot: 2016/09/03
        *TEXT_OFFSET : 0x8000 -> 커널 영역의 시작 주소
        *PG_DIR_SIZE : PTE의 크기 
        *phys + TEXT_OFFSET -> PTE 끝 물리 주소
        *PTE의 끝주소에서 PTE의 크기를 빼면 PTE의 물리 시작주소를 구할수 있음 
        @Iamroot 2016/09/03***/

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *
 * This code is mostly position independent, so if you link the kernel at
 * 0xc0008000, you call this at __pa(0xc0008000).	
	/*@Iamroot 
	 * __pa : build time에 결정되는 Physical Address. 지금은 kernel이 어디 위치에
	 *  돌아가는지 정확하게 알지만 Position Independent code로 작성함.
	 * 앞으로 Kernel이 시작되면서 mmu와 cache, 그리고 가상 메모리까지 설정할것이다. 
	 * Virtual Address 에서는 "c000 : user 영역과 kernel 영역의 경계"이 말이 맞는데,
	 * 여기서는 Physical Address이므로 상관 X. 
	 * 현 architecture DRAM의 시작주소가 단지 0xc0000000일뿐.
	 */
 *
 * See linux/arch/arm/tools/mach-types for the complete list of machine
 * numbers for r1.
 *
 * We're trying to keep crap to a minimum; DO NOT add any machine specific
 * crap here - that's what the boot loader (or in extreme, well justified
 * circumstances, zImage) is for.
 */
	.arm

	__HEAD
	/*@Iamroot
         * #define __HEAD		.section	".head.text","ax"
	 * ARMv7 Build시decompressed Kernel의 진짜시작주소 c0008000
	 */
ENTRY(stext)
 ARM_BE8(setend	be )			@ ensure we are in BE8 mode

 THUMB(	badr	r9, 1f		)	@ Kernel is always entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install
#endif
	@ ensure svc mode and all interrupts masked
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type		@ r5=procinfo r9=cpuid
	movs	r10, r5				@ invalid processor (r5=0)?
						/*
						 * if r5 == 0: Z bit set(Z)
						 * 아래의 beq __error_p가 실행
						 */
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p			@ yes, error 'p'

/*@Iamroot
 * LPAE(Large Physical Address Extensions)
 * 32bit arch에서는 최대 메모리 어드레싱 4GB, 그러나 실제로는 거의 2~3GB밖에 사용할 수 없다. 
 * 
 * LPAE를 활성화하면 물리주소의 비트수를 32bit-> 40bit까지 늘릴 수 있다.
 * 물리주소는 최대 2^40 (== 1TB), Virtual Memory는 32bit
 * Q) HW적인 조정이 필요하나? 
 * A) No, cpu가 지원만 해준다면, 커널에서 특정 비트 하나 set함으로써 LPAE를 활성화할 수 있다.
 *
 * Raspberry Pi2는 LPAE가 설정되어있지 않으므로 LPAE부분은 보지 않고 skip.
 */
#ifdef CONFIG_ARM_LPAE
	mrc	p15, 0, r3, c0, c1, 4		@ read ID_MMFR0
	and	r3, r3, #0xf			@ extract VMSA support
	cmp	r3, #5				@ long-descriptor translation table format?
 THUMB( it	lo )				@ force fixup-able long branch encoding
	blo	__error_lpae			@ only classic page table format
#endif

/*@Iamroot
 * CONFIG_XIP_KERNEL: Flash Memory에서 실행되는 것을 지원해주냐 안하느냐
 * 설정 안되어있다고 보고 진행
 */
#ifndef CONFIG_XIP_KERNEL
	adr	r3, 2f
	ldmia	r3, {r4, r8}
	sub	r4, r3, r4			@ (PHYS_OFFSET - PAGE_OFFSET)
	add	r8, r8, r4			@ PHYS_OFFSET
	/*
	 * r3 = 2f's physical address
	 * r4 = .
	 * r4 = (r3 - r4) (==delta) 
		Q: delta값 구하는로직은 매번똑같은데 왜 자꾸 계속구함???
		A: delta전용특정 레지스터나 스택 이용하는건 비효율적일 것.
	 * r8 = 0x8000 0000 (==PAGE_OFFSET, 즉 커널의 가상메모리 시작점)
	 * r8 = (r8 + r4) (== 0x8000 0000 + delta)
	 */
#else
	ldr	r8, =PLAT_PHYS_OFFSET		@ always constant in this case
#endif
	/*
	 * r1 = machine no, r2 = atags or dtb,
	 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
	 */
	bl	__vet_atags
#ifdef CONFIG_SMP_ON_UP
	bl	__fixup_smp
#endif
#ifdef CONFIG_ARM_PATCH_PHYS_VIRT
	bl	__fixup_pv_table
#endif
	bl	__create_page_tables

	/*
	 * The following calls CPU specific code in a position independent
	 * manner.  See arch/arm/mm/proc-*.S for details.  r10 = base of
	 * xxx_proc_info structure selected by __lookup_processor_type
	 * above.
	 *
	 * The processor init function will be called with:
	 *  r1 - machine type
	 *  r2 - boot data (atags/dt) pointer
	 *  r4 - translation table base (low word)
	 *  r5 - translation table base (high word, if LPAE)
	 *  r8 - translation table base 1 (pfn if LPAE)
	 *  r9 - cpuid
	 *  r13 - virtual address for __enable_mmu -> __turn_mmu_on
	 *
	 * On return, the CPU will be ready for the MMU to be turned on,
	 * r0 will hold the CPU control register value, r1, r2, r4, and
	 * r9 will be preserved.  r5 will also be preserved if LPAE.
	 */
	ldr	r13, =__mmap_switched		@ address to jump to after
						@ mmu has been enabled
	badr	lr, 1f				@ return (PIC) address
	/*@Iamroot 2016/09/10 
	 * ldr r13, =__map_swithed
	 * __mmap_swithed 가상 주소를 r13에 저장한다.
	 * 다만 왜 r13에 넣는지 이해할 수 없다????
	 * badr lr, 1f
	 * THUMB2 mode일 경우에는 불러들일 물리주소를 +1한 후 adr 명령어를 수행한다.
	 * 아닐 경우엔 adr 명령어와 동일하다.
	 * raspberry pi2에서는 THUMB2가 아니기 때문에 adr 명령어와 동일하다.
	 * PIC : Postition Independent Code
	 */
#ifdef CONFIG_ARM_LPAE
	mov	r5, #0				@ high TTBR0
	mov	r8, r4, lsr #12			@ TTBR1 is swapper_pg_dir pfn
#else
	mov	r8, r4				@ set TTBR1 to swapper_pg_dir
	/*@Iamroot 2016/09/10
	 * 물리 page table 시작 주소를 r8에 넣는다.
	 */

#endif
	ldr	r12, [r10, #PROCINFO_INITFUNC]
	add	r12, r12, r10
	ret	r12
	/*@Iamroot 2016/09/10
	 * ldr r12, [r10, #PROCINFO_INITFUNC]
	 * r12 = proc_info_list(r10)->__cpu_flush(#PROCINFO_INITFUNC) 
	 * r12 = __v7_ca7mp_setup - __v7_ca7mp_proc_info
	 * r10 = __v7_ca7mp_proc_info
	 * r12 = r12 + r10 = __v7_ca7mp_setup
	 * ret r12 연산은 __v7_ca7mp_setup으로 branch한다.
	 */
1:	b	__enable_mmu
ENDPROC(stext)
	.ltorg
#ifndef CONFIG_XIP_KERNEL
2:	.long	.
	.long	PAGE_OFFSET			/* Kernel Image의 가상메모리 시작주소 
						 * PAGE_OFFSET == 0xc0000000
						 */
#endif

/*
 * Setup the initial page tables.  We only setup the barest
 * amount which are required to get the kernel running, which
 * generally means mapping in the kernel code.
 *
 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
 *
 * Returns:
 *  r0, r3, r5-r7 corrupted
 *  r4 = physical page table address
 */
__create_page_tables:
	pgtbl	r4, r8				@ page table address
        /*** @Iamroot: 2016/09/03
        * pgtbl -> macro
        * r8 : phys_offset , 
        * r4 : physical 페이지 테이블 주소 
        @Iamroot 2016/09/03***/
	/*
	 * Clear the swapper page table
	 */
	mov	r0, r4
	mov	r3, #0
	add	r6, r0, #PG_DIR_SIZE
        /*** @Iamroot: 2016/09/03
        * r0 에 PTE의 시작주소를 넣음 
        * r3 를 0으로 초기화
        * r6 에는 (PTE의 시작 주소 + PTE의 사이즈 = )PTE의 끝 주소 를 집어넣음 
        @Iamroot 2016/09/03***/
1:	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	teq	r0, r6
	bne	1b
        /*** @Iamroot: 2016/09/03
        * PTE를 0으로 초기화 시키는 작업 
        * PTE의 시작 주소 부터 4씩 증가 시키면서 0을 넣는 작업을 4회 한후 
        * r0 와 r6를 비교하여 마지막 주소에 갔을때 루프를 정지한다 .
        * 굳이 4회를 반복하는 이유
        * 가설 1 : 16바이트(4회)와 16k를 매치 시키기 위해 
        @Iamroot 2016/09/03***/

#ifdef CONFIG_ARM_LPAE
	/*
	 * Build the PGD table (first level) to point to the PMD table. A PGD
	 * entry is 64-bit wide.
	 */
	mov	r0, r4
	add	r3, r4, #0x1000			@ first PMD table address
	orr	r3, r3, #3			@ PGD block type
	mov	r6, #4				@ PTRS_PER_PGD
	mov	r7, #1 << (55 - 32)		@ L_PGD_SWAPPER
1:
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4			@ set top PGD entry bits
	str	r3, [r0], #4			@ set bottom PGD entry bits
#else
	str	r3, [r0], #4			@ set bottom PGD entry bits
	str	r7, [r0], #4			@ set top PGD entry bits
#endif
	add	r3, r3, #0x1000			@ next PMD table
	subs	r6, r6, #1
	bne	1b

	add	r4, r4, #0x1000			@ point to the PMD tables
#ifdef CONFIG_CPU_ENDIAN_BE8
	add	r4, r4, #4			@ we only write the bottom word
#endif
#endif

	ldr	r7, [r10, #PROCINFO_MM_MMUFLAGS] @ mm_mmuflags
        /*** @Iamroot: 2016/09/03
        * r10 : proc info list의 주소 
        * #PROCINFO_MM_MMUFLAGS  
        * DEFINE(PROCINFO_MM_MMUFLAGS,    offsetof(struct proc_info_list, __cpu_mm_mmu_flags))
        * proc_info_list의 __cpu_mm_mmu_flags의 offset을 PROCINFO_MM_MMUFLAGS에 정의 한다
        * offsetof ->  project/linux/include/linux/kbuild.h
        * 참고 : ALT_UP(.long    PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | \
                    PMD_SECT_AF | PMD_FLAGS_UP | \mm_mmuflags)
        @Iamroot 2016/09/03***/

	/*
	 * Create identity mapping to cater for __enable_mmu.
	 * This identity mapping will be removed by paging_init().
	 */
	adr	r0, __turn_mmu_on_loc
	ldmia	r0, {r3, r5, r6}
        /*** @Iamroot: 2016/09/03
        * turn_mmu_on_loc의 주소를 r0에 넣고 
        * r0 : __turn_mmu_on_loc 's phy address
        * r3 : .
        * r5 : __turn_mmu_on
        * r6 : __turn_mmu_on_end
        @Iamroot 2016/09/03***/
	sub	r0, r0, r3			@ virt->phys offset
	add	r5, r5, r0			@ phys __turn_mmu_on
	add	r6, r6, r0			@ phys __turn_mmu_on_end
	mov	r5, r5, lsr #SECTION_SHIFT      @ arch/arm/include/asm/pgtable-2level.h
	mov	r6, r6, lsr #SECTION_SHIFT      @ SECTION_SHIFT : 20 
        /*** @Iamroot: 2016/09/03
        * 물리주소 에서 가상주소를 빼 offset을 구하여 r0에 넣는다 
        * offset과 __turn_mmu_on의 가상주소를 더하여 _turn_mmu_on 의 물리주소를 r5에 저장
        * offset과 __turn_mmu_on_end의 가상주소를 더하여 _turn_mmu_on_end 의 물리주소를 r5에 저장
        * LPAE를 사용할경우 SECTION_SHIFT는 pgtable-3level.h를 참조 
        * section base addeess 가 31 ~ 20 까지의 비트이므로 그 외 필요 없는 비트들을 전부 
        * 날려버리기 위해 SECTION_SHIFT 만큼 SHIFT 한다 
        @Iamroot 2016/09/03***/

1:	orr	r3, r7, r5, lsl #SECTION_SHIFT	@ flags + kernel base
        /*** @Iamroot: 2016/09/03
        * SECTION_SHIFT만큼 다시 r5를 조정하여 
        * 19~0 까지의 하위비트를 전부 0으로 채우고 r7와 or연산하여 r3에 넣는다
        * r7 : mm_mmuflags
        @Iamroot 2016/09/03***/
	str	r3, [r4, r5, lsl #PMD_ORDER]	@ identity mapping
	cmp	r5, r6
	addlo	r5, r5, #1			@ next section
	blo	1b
        /*** @Iamroot: 2016/09/03
        * #PMD_ORDER : 2 
        * r4 : PTE의 시작 주소 
        * r4와 r5를 2번 shift한 값과 더한 곳(주소)에 r3를 저장 한다 
        * r5에 1바이트씩 더하여 2씩 shift하면 4씩 증가하는 결과가 된다 
        * turn_mmu_on 과 turn_mmu_on_end 사이의 한 섹션에 대하여 맵핑  
        * __turn_mmu_on 의 의미를 알 필요가 있음 ????????  
        @Iamroot 2016/09/03***/

	/*
	 * Map our RAM from the start to the end of the kernel .bss section.
	 */
	add	r0, r4, #PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER)
        /*** @Iamroot: 2016/09/10
        * page_offset(0x80000000) >> 18 = 0x2000
        * r4 : PTE의 시작의 물리 주소 = 0x0000_4000 
		* r0 = 0x0000_6000
        * PMD : page middle directory
        * PGD : page global directory
        * PTE : page table entry
		* 가상 주소에서 PTE를 만든게 아니라 물리 주소에서 PTE를 만들었기 때문에
		* r4가 0x8000_4000이 아니라 0x0000_4000이 된다.
		* r4의 가상주소가 어디에 맵핑되었는지 확인해서 r0에 저장한다.
        @Iamroot 2016/09/10***/
	ldr	r6, =(_end - 1)
		/* @Iamroot 2016/09/10
		 * r6 = bss section의 마지막 주소 - 1
		 * 커널 영역에서 bss까지 0x8000 가상 주소와 0x0000 물리 주소를 매핑한다.
		 */
	orr	r3, r8, r7
		/*@Iamroot 2016/09/10
		 * PTE를 만드는 작업을 한다.
	     */
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
		/* @Iamroot 2016/09/10
		 * 해당 연산을 통해 r6은 (_end-1) Page Table가 매핑된 가상주소가 나온다.
		 * r6의 가상주소가 어디에 맵핑되었는지 확인해서 r6에 저장한다.
		 */
1:	str	r3, [r0], #1 << PMD_ORDER
	add	r3, r3, #1 << SECTION_SHIFT
	cmp	r0, r6
	bls	1b
		/*** @Iamroot: 2016/09/10 
      	 *  r7 : phy offset 
         *	r8 : 0x0000_0000
		 *	Page table(r0)에 PTE 내용(r3)을 쓰고 r0 = r0 + 4를 수행한다.
		 *	PTE 내용에서 PA에 해당하는 값을 1mb를 증가시킨다.(PA = PA + 2^20)
		 *	PTE 주소가 _end까지 도달했는지 확인 후
		 *	도달 후 넘어갔을 때 끝나고 도달하지 않거나 도달했을 경우 앞의 1: 연산을 반복한다. 
		@Iamroot 2016/09/10***/

#ifdef CONFIG_XIP_KERNEL
	/*
	 * Map the kernel image separately as it is not located in RAM.
	 */
#define XIP_START XIP_VIRT_ADDR(CONFIG_XIP_PHYS_ADDR)
	mov	r3, pc
	mov	r3, r3, lsr #SECTION_SHIFT
	orr	r3, r7, r3, lsl #SECTION_SHIFT
	add	r0, r4,  #(XIP_START & 0xff000000) >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0, #((XIP_START & 0x00f00000) >> SECTION_SHIFT) << PMD_ORDER]!
	ldr	r6, =(_edata_loc - 1)
	add	r0, r0, #1 << PMD_ORDER
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	cmp	r0, r6
	add	r3, r3, #1 << SECTION_SHIFT
	strls	r3, [r0], #1 << PMD_ORDER
	bls	1b
#endif

	/*
	 * Then map boot params address in r2 if specified.
	 * We map 2 sections in case the ATAGs/DTB crosses a section boundary.
	 */
/*** @Iamroot: 2016/09/24
        1section : 1MB
@Iamroot 2016/09/24***/
	mov	r0, r2, lsr #SECTION_SHIFT
	movs	r0, r0, lsl #SECTION_SHIFT
	/*@Iamroot 2016/09/10
	 * r2 : ATAG/DTB의 물리주소
	 * r0 : DTB의 시작 물리주소
	 * r2에 값이 있는 경우는 DTB가 존재하고 0인 경우에는 DTB가 존재하지 않는다.
	 * 이 원리를 이용해서 DTB가 존재하는 경우 아래 *ne연산을 수행하고 아니면 넘어간다.
	 */
	subne	r3, r0, r8
	addne	r3, r3, #PAGE_OFFSET
	addne	r3, r4, r3, lsr #(SECTION_SHIFT - PMD_ORDER)
	orrne	r6, r7, r0
	strne	r6, [r3], #1 << PMD_ORDER
	addne	r6, r6, #1 << SECTION_SHIFT
	strne	r6, [r3]
	/*@Iamroot 2016/09/10
	 * r8 = kernel의 시작주소
	 * subne를 이용해서 kernel 시작주소와 DTB의 시작주소의 offset를 구한다.
	 * 이후 DTB의 가상주소를 구해서 Page Table에 물리주소와 함께 매핑한다.
	 * 매핑하는 값은 r6이며 r3에 4를 증가한다.
	 * 그리고 r3 주소에 2^20을 추가해서 매핑값에 저장한다.
	 * DTB는 2MB 이하인걸로 가정해서 str연산을 두 번만 수행한다.
	 */

#if defined(CONFIG_ARM_LPAE) && defined(CONFIG_CPU_ENDIAN_BE8)
	sub	r4, r4, #4			@ Fixup page table pointer
						@ for 64-bit descriptors
#endif

#ifdef CONFIG_DEBUG_LL
#if !defined(CONFIG_DEBUG_ICEDCC) && !defined(CONFIG_DEBUG_SEMIHOSTING)
	/*
	 * Map in IO space for serial debugging.
	 * This allows debug messages to be output
	 * via a serial console before paging_init.
	 */
	addruart r7, r3, r0

	mov	r3, r3, lsr #SECTION_SHIFT
	mov	r3, r3, lsl #PMD_ORDER

	add	r0, r4, r3
	mov	r3, r7, lsr #SECTION_SHIFT
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
	orr	r3, r7, r3, lsl #SECTION_SHIFT
#ifdef CONFIG_ARM_LPAE
	mov	r7, #1 << (54 - 32)		@ XN
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4
	str	r3, [r0], #4
#else
	str	r3, [r0], #4
	str	r7, [r0], #4
#endif
#else
	orr	r3, r3, #PMD_SECT_XN
	str	r3, [r0], #4
#endif

#else /* CONFIG_DEBUG_ICEDCC || CONFIG_DEBUG_SEMIHOSTING */
	/* we don't need any serial debugging mappings */
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
#endif

#if defined(CONFIG_ARCH_NETWINDER) || defined(CONFIG_ARCH_CATS)
	/*
	 * If we're using the NetWinder or CATS, we also need to map
	 * in the 16550-type serial port for the debug messages
	 */
	add	r0, r4, #0xff000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x7c000000
	str	r3, [r0]
#endif
#ifdef CONFIG_ARCH_RPC
	/*
	 * Map in screen at 0x02000000 & SCREEN2_BASE
	 * Similar reasons here - for debug.  This is
	 * only for Acorn RiscPC architectures.
	 */
	add	r0, r4, #0x02000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x02000000
	str	r3, [r0]
	add	r0, r4, #0xd8000000 >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0]
#endif
#endif
#ifdef CONFIG_ARM_LPAE
	sub	r4, r4, #0x1000		@ point to the PGD table
#endif
	ret	lr
ENDPROC(__create_page_tables)
	.ltorg
	.align
__turn_mmu_on_loc:
	.long	.
	.long	__turn_mmu_on
	.long	__turn_mmu_on_end

#if defined(CONFIG_SMP)
	.text
	.arm
ENTRY(secondary_startup_arm)
 THUMB(	badr	r9, 1f		)	@ Kernel is entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)
ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 *
	 * Ensure that we're in SVC mode, and IRQs are disabled.  Lookup
	 * the processor type - there is no need to check the machine type
	 * as it has already been validated by the primary processor.
	 */

 ARM_BE8(setend	be)				@ ensure we are in BE8 mode

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type
	movs	r10, r5				@ invalid processor?
	moveq	r0, #'p'			@ yes, error 'p'
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p

	/*
	 * Use the page tables supplied from  __cpu_up.
	 */
	adr	r4, __secondary_data
	ldmia	r4, {r5, r7, r12}		@ address to jump to after
	sub	lr, r4, r5			@ mmu has been enabled
	add	r3, r7, lr
	ldrd	r4, [r3, #0]			@ get secondary_data.pgdir
ARM_BE8(eor	r4, r4, r5)			@ Swap r5 and r4 in BE:
ARM_BE8(eor	r5, r4, r5)			@ it can be done in 3 steps
ARM_BE8(eor	r4, r4, r5)			@ without using a temp reg.
	ldr	r8, [r3, #8]			@ get secondary_data.swapper_pg_dir
	badr	lr, __enable_mmu		@ return address
	mov	r13, r12			@ __secondary_switched address
	ldr	r12, [r10, #PROCINFO_INITFUNC]
	add	r12, r12, r10			@ initialise processor
						@ (return control reg)
	ret	r12
ENDPROC(secondary_startup)
ENDPROC(secondary_startup_arm)

	/*
	 * r6  = &secondary_data
	 */
ENTRY(__secondary_switched)
	ldr	sp, [r7, #12]			@ get secondary_data.stack
	mov	fp, #0
	b	secondary_start_kernel
ENDPROC(__secondary_switched)

	.align

	.type	__secondary_data, %object
__secondary_data:
	.long	.
	.long	secondary_data
	.long	__secondary_switched
#endif /* defined(CONFIG_SMP) */



/*
 * Setup common bits before finally enabling the MMU.  Essentially
 * this is just loading the page table pointer and domain access
 * registers.  All these registers need to be preserved by the
 * processor setup function (or set in the case of r0)
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r4  = TTBR pointer (low word)
 *  r5  = TTBR pointer (high word if LPAE)
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 */
__enable_mmu:
#if defined(CONFIG_ALIGNMENT_TRAP) && __LINUX_ARM_ARCH__ < 6
	orr	r0, r0, #CR_A
#else
	bic	r0, r0, #CR_A
#endif
#ifdef CONFIG_CPU_DCACHE_DISABLE
	bic	r0, r0, #CR_C
#endif
#ifdef CONFIG_CPU_BPREDICT_DISABLE
	bic	r0, r0, #CR_Z
#endif
#ifdef CONFIG_CPU_ICACHE_DISABLE
	bic	r0, r0, #CR_I
#endif
#ifdef CONFIG_ARM_LPAE
	mcrr	p15, 0, r4, r5, c2		@ load TTBR0
#else
	mov	r5, #DACR_INIT
	mcr	p15, 0, r5, c3, c0, 0		@ load domain access register
	mcr	p15, 0, r4, c2, c0, 0		@ load page table pointer
#endif
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU.  This completely changes the structure of the visible
 * memory space.  You will not be able to trace execution through this.
 * If you have an enquiry about this, *please* check the linux-arm-kernel
 * mailing list archives BEFORE sending another post to the list.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 */
	.align	5
	.pushsection	.idmap.text, "ax"
ENTRY(__turn_mmu_on)
	mov	r0, r0
	instr_sync
	mcr	p15, 0, r0, c1, c0, 0		@ write control reg
	mrc	p15, 0, r3, c0, c0, 0		@ read id reg
	instr_sync
	mov	r3, r3
	mov	r3, r13
	ret	r3
__turn_mmu_on_end:
ENDPROC(__turn_mmu_on)
	.popsection


#ifdef CONFIG_SMP_ON_UP
	__HEAD
__fixup_smp:
	and	r3, r9, #0x000f0000	@ architecture version
	teq	r3, #0x000f0000		@ CPU ID supported?
					/* if r3 == 0x000f0000
					      Z bit SET */
	bne	__fixup_smp_on_up	@ no, assume UP
/* ARMv7에서는 Z bit가 SET되므로 branch 하지 않고 바로 내려간다*/
	bic	r3, r9, #0x00ff0000
	bic	r3, r3, #0x0000000f	@ mask 0xff00fff0
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000b000
	orr	r4, r4, #0x00000020	@ val 0x4100b020
	teq	r3, r4			@ ARM 11MPCore?
	reteq	lr			@ yes, assume SMP

	mrc	p15, 0, r0, c0, c0, 5	@ read MPIDR
	and	r0, r0, #0xc0000000	@ multiprocessing extensions and
	teq	r0, #0x80000000		@ not part of a uniprocessor system?
					/* Ubit(==bit[30])를 보고 SMP인지 아닌지 점검
					 * Ubit == 0 이면 SMP, UBit== 1 이면 UP
					 * 현재 r0이 SMP이면 r0 == 0x80000000
					 *            UP이면 r0 == 0xc0000000
					 */
	bne    __fixup_smp_on_up	@ no, assume UP

	@ Core indicates it is SMP. Check for Aegis SOC where a single
	@ Cortex-A9 CPU is present but SMP operations fault.
	mov	r4, #0x41000000
	orr	r4, r4, #0x0000c000
	orr	r4, r4, #0x00000090	/* r4 == 0x4100c090 */
	teq	r3, r4			@ Check for ARM Cortex-A9
	retne	lr			@ Not ARM Cortex-A9,

	@ If a future SoC *does* use 0x0 as the PERIPH_BASE, then the
	@ below address check will need to be #ifdef'd or equivalent
	@ for the Aegis platform.
	/**/
	mrc	p15, 4, r0, c15, c0	@ get SCU base address
					/* c15에 대해서는 cpu에 따라 정의가 달라진다.*/
	teq	r0, #0x0		@ '0' on actual UP A9 hardware
	beq	__fixup_smp_on_up	@ So its an A9 UP
	ldr	r0, [r0, #4]		@ read SCU Config
ARM_BE8(rev	r0, r0)			@ byteswap if big endian
	and	r0, r0, #0x3		@ number of CPUs
	teq	r0, #0x0		@ is 1?
	retne	lr

__fixup_smp_on_up:
	adr	r0, 1f
	ldmia	r0, {r3 - r5}
	sub	r3, r0, r3	@Iamroot r3=r0-r3를 저장해서 오프셋 주소를 구한다.
	add	r4, r4, r3  @Iamroot r4=r4+r3를 저장한다. smpalt_begin의 실제 주소를 구한다.
	add	r5, r5, r3  @Iamroot r5=r5+r3를 저장한다. smpalt_end의 실제 주소를 구한다.
	b	__do_fixup_smp_on_up
ENDPROC(__fixup_smp)

	.align
1:	.word	.
	.word	__smpalt_begin
	.word	__smpalt_end

	.pushsection .data
	.globl	smp_on_up
smp_on_up:
	ALT_SMP(.long	1)
	ALT_UP(.long	0)
	.popsection
#endif

	.text
__do_fixup_smp_on_up:
	/* r4 = __smpalt_begin의 물리주소, r5 = __smpalt_end의 물리 주소*/	
	cmp	r4, r5
	reths	lr
	ldmia	r4!, {r0, r6}
	/*
	 * r0 == 9998 label's virtual address 
	 * r6 == 9997 label에 있는 해당 instr 데이터
	 * Right Here!
	 */
 ARM(	str	r6, [r0, r3]	) /*proc_type*/
	/*@Iamroot
	 * r6 => r0(9998 가상주소) + r3(오프셋)을 넣는다.
	 * 이렇게 되면 r6은 9998의 실제주소가 된다.
	 */
 THUMB(	add	r0, r0, r3	)
#ifdef __ARMEB__
 THUMB(	mov	r6, r6, ror #16	)	@ Convert word order for big-endian.
#endif
 THUMB(	strh	r6, [r0], #2	)	@ For Thumb-2, store as two halfwords
 THUMB(	mov	r6, r6, lsr #16	)	@ to be robust against misaligned r3.
 THUMB(	strh	r6, [r0]	)
	b	__do_fixup_smp_on_up
ENDPROC(__do_fixup_smp_on_up)

ENTRY(fixup_smp)
	stmfd	sp!, {r4 - r6, lr}
	mov	r4, r0
	add	r5, r0, r1
	mov	r3, #0
	bl	__do_fixup_smp_on_up
	ldmfd	sp!, {r4 - r6, pc}
ENDPROC(fixup_smp)

#ifdef __ARMEB__
#define LOW_OFFSET	0x4
#define HIGH_OFFSET	0x0
#else
#define LOW_OFFSET	0x0
#define HIGH_OFFSET	0x4
#endif

#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

/* __fixup_pv_table - patch the stub instructions with the delta between
 * PHYS_OFFSET and PAGE_OFFSET, which is assumed to be 16MiB aligned and
 * can be expressed by an immediate shifter operand. The stub instruction
 * has a form of '(add|sub) rd, rn, #imm'.
 */
	__HEAD
__fixup_pv_table:
	/*@Iamroot
	 * pv_table은 physical_memory주소에서  virtual_memory주소로 변환하거나
	 * virtual_memory주소에서 physical_memory주소로 변환시 참조하는 테이블이다.
	 * 테이블 안에는 pv_stub instruction의 memory주소가 들어있다.
	 * fixup_pv_table은 delta offset, page frame number, page start/end address 값을 구하는 역할을 수행한다.
	 * fixup_a_pv_table은 pv_table의 __PV_BITS_31_24(memory.h)를 계산된 delta offset 주소로 변경하는 역할을 수행한다.
	 */
	adr	r0, 1f
	ldmia	r0, {r3-r7}
	mvn	ip, #0 @Iamroot mov ip, #0xffffffff 와 같은 의미, ip의 의미는 Google Docs 'AAPCS ip(r12 register) 의미' 참고
	subs	r3, r0, r3	@ PHYS_OFFSET - PAGE(VIRT)_OFFSET; 즉, delta offset이다.
	add	r4, r4, r3	@ adjust table start address
	add	r5, r5, r3	@ adjust table end address
	add	r6, r6, r3	@ adjust __pv_phys_pfn_offset address
	add	r7, r7, r3	@ adjust __pv_offset address
	mov	r0, r8, lsr #PAGE_SHIFT	@ convert to PFN
	/*@Iamroot
	 * r8 = 0xc0000000로 되어있는데 right shift를 12(PAGE_SHIFT)번을 수행한다.
	 * 이후, 수행한 값을 r0(Page Frame Number=PFN)에 넣는다.
	 */
	str	r0, [r6]	@ save computed PHYS_OFFSET to __pv_phys_pfn_offset
	strcc	ip, [r7, #HIGH_OFFSET]	@ save to __pv_offset high bits
	/*@Iamroot
	 * r7 주소+#4에 ip(0xffffffff)를 저장한다. 다만 해당 명령어를 실행하는 조건은 C flag=0
	 * 하는 이유는 LPAE(64비트)일 경우를 고려하기 위해서
	 * subs 연산 결과에서 PHYS_OFFSET가 VIRT_OFFSET보다 작을 때 상위 4바이트를 -1로 세팅함
	 * PA를 구할 때 delta와 VA를 더하는데 이 때 발생되는 carry를 고려한 연산
	 * Google Docs '6.4 a carry occurs' 참고
	 */
	mov	r6, r3, lsr #24	@ constant for add/sub instructions 
	teq	r3, r6, lsl #24 @ must be 16MiB aligned
	/*@Iamroot
	 * add, sub연산에서 immediate value는 8비트까지 인식이 가능하다.
	 * 16MB로 aligned가 안되었다면 __error루틴으로 간다. 
	 */
THUMB(	it	ne		@ cross section branch )
	bne	__error
	str	r3, [r7, #LOW_OFFSET]	@ save to __pv_offset low bits
	b	__fixup_a_pv_table
ENDPROC(__fixup_pv_table)

	.align
1:	.long	.
	.long	__pv_table_begin
	.long	__pv_table_end
2:	.long	__pv_phys_pfn_offset
	.long	__pv_offset

	.text
__fixup_a_pv_table:
	adr	r0, 3f
	ldr	r6, [r0]
	add	r6, r6, r3
	ldr	r0, [r6, #HIGH_OFFSET]	@ pv_offset high word
	ldr	r6, [r6, #LOW_OFFSET]	@ pv_offset low word
	mov	r6, r6, lsr #24
	cmn	r0, #1 @Iamroot cmn=adds와 같은 의미(r0=0xffffffff)
#ifdef CONFIG_THUMB2_KERNEL
	moveq	r0, #0x200000	@ set bit 21, mov to mvn instruction
	lsls	r6, #24
	beq	2f
	clz	r7, r6
	lsr	r6, #24
	lsl	r6, r7
	bic	r6, #0x0080
	lsrs	r7, #1
	orrcs	r6, #0x0080
	orr	r6, r6, r7, lsl #12
	orr	r6, #0x4000
	b	2f
1:	add     r7, r3
	ldrh	ip, [r7, #2]
ARM_BE8(rev16	ip, ip)
	tst	ip, #0x4000
	and	ip, #0x8f00
	orrne	ip, r6	@ mask in offset bits 31-24
	orreq	ip, r0	@ mask in offset bits 7-0
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7, #2]
	bne	2f
	ldrh	ip, [r7]
ARM_BE8(rev16	ip, ip)
	bic	ip, #0x20
	orr	ip, ip, r0, lsr #16
ARM_BE8(rev16	ip, ip)
	strh	ip, [r7]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	/*@Iamroot
	 이쪽에서부터 런타임이 시작될 때 /arch/arm/include/asm/memory.h에 있는 'static inline phys_addr_t __virt_to_phys'에 접근한다.
	 */
	bcc	1b
	bx	lr
#else
#ifdef CONFIG_CPU_ENDIAN_BE8
	moveq	r0, #0x00004000	@ set bit 22, mov to mvn instruction
#else
	moveq	r0, #0x400000	@ set bit 22, mov to mvn instruction
	/*@Iamroot
	 * Raspberry pi2가 LITTLE ENDIAN이기 때문에 #else 루틴으로 빠짐
	 * cmn연산결과 Z플래그 set되기 때문에 moveq 명령어는 실행함 
	 */
#endif
	b	2f
1:	ldr	ip, [r7, r3] @Iamroot ip => pv_table_begin의 VIRT_ADDRESS + delta offset
        /*** @Iamroot: 2016/09/03
        * r7(pv_table_begin 의 가상주소)에  delta-offset을 더해 pv_table에 저장되어 있는 instruction을 불러옴 
        @Iamroot 2016/09/03***/
#ifdef CONFIG_CPU_ENDIAN_BE8
	@ in BE8, we load data in BE, but instructions still in LE
	bic	ip, ip, #0xff000000
	tst	ip, #0x000f0000	@ check the rotation field
	orrne	ip, ip, r6, lsl #24 @ mask in offset bits 31-24
	biceq	ip, ip, #0x00004000 @ clear bit 22
	orreq	ip, ip, r0      @ mask in offset bits 7-0
#else
	bic	ip, ip, #0x000000ff
	tst	ip, #0xf00	@ check the rotation field
        /*** @Iamroot: 2016/09/03
        * 현재 ip는 pv_table에서 가져온 instruction
        * 하위 8비트(immediate 값) 클리어 
        * rotation field(9 ~ 12비트)에 있는 값과 0xf00을 비교 manual p.200
        * 0x'f'00 -> 1111 과 ip의 9~12비트를 and 연산하여 결과가 0000 일 경우 eq, 아닐경우 ne 실행
        @Iamroot 2016/09/03***/
	orrne	ip, ip, r6	@ mask in offset bits 31-24
	biceq	ip, ip, #0x400000	@ clear bit 22
	orreq	ip, ip, r0	@ mask in offset bits 7-0
        /*** @Iamroot: 2016/09/03
        * r6 : pv_offset의 row 비트
        * 하위 8비트를 pv_offset(r6)과 orr연산
        * -> immediate의 값을 변경
        * eq 명령어들(biceq, orreq)은 64비트 일경우
        * 64비트일경우 rotation field가 0000
        * 32비트일경우 rotation field를 반드시 써야 하기 때문에 
        @Iamroot 2016/09/03***/
#endif
	str	ip, [r7, r3]
	/*@Iamroot
	 * r4 = PV_TABLE_BEGIN
	 * r5 = PV_TABLE_END
	 */
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	/*@Iamroot
	 * PV_TABLE_BEGIN부터 주소값을 읽어서 r7에 넣고 r4에 4를 더함
	 */
	ret	lr
#endif
ENDPROC(__fixup_a_pv_table)

	.align
3:	.long __pv_offset

ENTRY(fixup_pv_table)
	stmfd	sp!, {r4 - r7, lr}
	mov	r3, #0			@ no offset
	mov	r4, r0			@ r0 = table start
	add	r5, r0, r1		@ r1 = table size
	bl	__fixup_a_pv_table
	ldmfd	sp!, {r4 - r7, pc}
ENDPROC(fixup_pv_table)

	.data
	.globl	__pv_phys_pfn_offset
	.type	__pv_phys_pfn_offset, %object
__pv_phys_pfn_offset:
	.word	0
	.size	__pv_phys_pfn_offset, . -__pv_phys_pfn_offset

	.globl	__pv_offset
	.type	__pv_offset, %object
__pv_offset:
	.quad	0
	.size	__pv_offset, . -__pv_offset
#endif

#include "head-common.S"
