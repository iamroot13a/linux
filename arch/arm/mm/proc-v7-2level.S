/*
 * arch/arm/mm/proc-v7-2level.S
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define TTB_S		(1 << 1)
#define TTB_RGN_NC	(0 << 3)
#define TTB_RGN_OC_WBWA	(1 << 3)
#define TTB_RGN_OC_WT	(2 << 3)
#define TTB_RGN_OC_WB	(3 << 3)
#define TTB_NOS		(1 << 5)
#define TTB_IRGN_NC	((0 << 0) | (0 << 6))
#define TTB_IRGN_WBWA	((0 << 0) | (1 << 6))
#define TTB_IRGN_WT	((1 << 0) | (0 << 6))
#define TTB_IRGN_WB	((1 << 0) | (1 << 6))

/* PTWs cacheable, inner WB not shareable, outer WB not shareable */
#define TTB_FLAGS_UP	TTB_IRGN_WB|TTB_RGN_OC_WB
#define PMD_FLAGS_UP	PMD_SECT_WB

/* PTWs cacheable, inner WBWA shareable, outer WBWA not shareable */
#define TTB_FLAGS_SMP	TTB_IRGN_WBWA|TTB_S|TTB_NOS|TTB_RGN_OC_WBWA
/*@Iamroot 2016/10/08
 * TTB1[6:0]에 들어갈 값을 Setting한다.
 */

#define PMD_FLAGS_SMP	PMD_SECT_WBWA|PMD_SECT_S

/*
 *	cpu_v7_switch_mm(pgd_phys, tsk)
 *
 *	Set the translation table base pointer to be pgd_phys
 *
 *	- pgd_phys - physical address of new TTB
 *
 *	It is assumed that:
 *	- we are not using split page tables
 *
 *	Note that we always need to flush BTAC/BTB if IBE is set
 *	even on Cortex-A8 revisions not affected by 430973.
 *	If IBE is not set, the flush BTAC/BTB won't do anything.
 */
ENTRY(cpu_ca8_switch_mm)
#ifdef CONFIG_MMU
	mov	r2, #0
	mcr	p15, 0, r2, c7, c5, 6		@ flush BTAC/BTB
#endif
ENTRY(cpu_v7_switch_mm)
#ifdef CONFIG_MMU
	mmid	r1, r1				@ get mm->context.id
	ALT_SMP(orr	r0, r0, #TTB_FLAGS_SMP)
	ALT_UP(orr	r0, r0, #TTB_FLAGS_UP)
#ifdef CONFIG_PID_IN_CONTEXTIDR
	mrc	p15, 0, r2, c13, c0, 1		@ read current context ID
	lsr	r2, r2, #8			@ extract the PID
	bfi	r1, r2, #8, #24			@ insert into new context ID
#endif
#ifdef CONFIG_ARM_ERRATA_754322
	dsb
#endif
	mcr	p15, 0, r1, c13, c0, 1		@ set context ID
	isb
	mcr	p15, 0, r0, c2, c0, 0		@ set TTB 0
	isb
#endif
	bx	lr
ENDPROC(cpu_v7_switch_mm)
ENDPROC(cpu_ca8_switch_mm)

/*
 *	cpu_v7_set_pte_ext(ptep, pte)
 *
 *	Set a level 2 translation table entry.
 *
 *	- ptep  - pointer to level 2 translation table entry
 *		  (hardware version is stored at +2048 bytes)
 *	- pte   - PTE value to store
 *	- ext	- value for extended PTE bits
 */
ENTRY(cpu_v7_set_pte_ext)
#ifdef CONFIG_MMU
	str	r1, [r0]			@ linux version

	bic	r3, r1, #0x000003f0
	bic	r3, r3, #PTE_TYPE_MASK
#if 0  /* @Iamroot: 2017.05.13 */
        r0에 r1을 저장(mapping)
        r1에서 5~10번째 비트를 클리어 한후 r3에 저장한다
        r3에서 1~2번째 비트를 클리어한다

        r0 : pte : pte의 주소
        r1 : pfn_pte(pfn, __pgprot(type->prot_pte)
        r2 : ng ? PTE_EXT_NG : 0  -> 0 
#endif /* @Iamroot  */
	orr	r3, r3, r2
	orr	r3, r3, #PTE_EXT_AP0 | 2
#if 0  /* @Iamroot: 2017.05.13 */
        read 또는 read/write 권한을 주기위해 EXT_AP0을 설정하고 
        2차 테이블을 지원하기 위해 TABLE 비트를 설정한다. 
#endif /* @Iamroot  */

	tst	r1, #1 << 4
	orrne	r3, r3, #PTE_EXT_TEX(1)
#if 0  /* @Iamroot: 2017.05.13 */
       r1의 4번째 비트가 1인 경우 첫번째 TEX 비트를 설정한다
#endif /* @Iamroot  */

	eor	r1, r1, #L_PTE_DIRTY
	tst	r1, #L_PTE_RDONLY | L_PTE_DIRTY
	orrne	r3, r3, #PTE_EXT_APX
#if 0  /* @Iamroot: 2017.05.13 */
        DIRTY비트가 없거나 RDONLY 비트가 있을경우 APX비트를 설정한다.
#endif /* @Iamroot  */
	tst	r1, #L_PTE_USER
	orrne	r3, r3, #PTE_EXT_AP1

	tst	r1, #L_PTE_XN
	orrne	r3, r3, #PTE_EXT_XN
#if 0  /* @Iamroot: 2017.05.13 */
        L_PTE_USER와 L_PTE_XN가 설정 되어있을경우 AP1과 XN비트를 설정한다
#endif /* @Iamroot  */
	tst	r1, #L_PTE_YOUNG
	tstne	r1, #L_PTE_VALID
	eorne	r1, r1, #L_PTE_NONE
	tstne	r1, #L_PTE_NONE
	moveq	r3, #0
#if 0  /* @Iamroot: 2017.05.13 */
        pte의 L_PTE_YOUNG이 없거나 L_PTE_VALID(L_PTE_PRESENT)가 없거나 
        L_PTE_NONE이 있으면 r3을 모두 0으로 변경
#endif /* @Iamroot  */

 ARM(	str	r3, [r0, #2048]! )
#if 0  /* @Iamroot: 2017.05.13 */
    r0에 저장되어 있는 주소는 linux pte의 주소이며 현재 r3는 h/w pte 이므로 
    linux pte 주소에 2048(512 * 4) 만큼 더하여 h/w pte의 주소에 r3를 저장 한다 
#endif /* @Iamroot  */
 THUMB(	add	r0, r0, #2048 )
 THUMB(	str	r3, [r0] )
	ALT_SMP(W(nop))
	ALT_UP (mcr	p15, 0, r0, c7, c10, 1)		@ flush_pte
#endif
	bx	lr
ENDPROC(cpu_v7_set_pte_ext)

	/*
	 * Memory region attributes with SCTLR.TRE=1
	 *
	 *   n = TEX[0],C,B
	 *   TR = PRRR[2n+1:2n]		- memory type
	 *   IR = NMRR[2n+1:2n]		- inner cacheable property
	 *   OR = NMRR[2n+17:2n+16]	- outer cacheable property
	 *
	 *			n	TR	IR	OR
	 *   UNCACHED		000	00
	 *   BUFFERABLE		001	10	00	00
	 *   WRITETHROUGH	010	10	10	10
	 *   WRITEBACK		011	10	11	11
	 *   reserved		110
	 *   WRITEALLOC		111	10	01	01
	 *   DEV_SHARED		100	01
	 *   DEV_NONSHARED	100	01
	 *   DEV_WC		001	10
	 *   DEV_CACHED		011	10
	 *
	 * Other attributes:
	 *
	 *   DS0 = PRRR[16] = 0		- device shareable property
	 *   DS1 = PRRR[17] = 1		- device shareable property
	 *   NS0 = PRRR[18] = 0		- normal shareable property
	 *   NS1 = PRRR[19] = 1		- normal shareable property
	 *   NOS = PRRR[24+n] = 1	- not outer shareable
	 */
.equ	PRRR,	0xff0a81a8
.equ	NMRR,	0x40e040e0
/*@Iamroot 2016/10/08
 * equ는 #define의 어셈블리어화 시킨 gas 디렉티브
 */

	/*
	 * Macro for setting up the TTBRx and TTBCR registers.
	 * - \ttb0 and \ttb1 updated with the corresponding flags.
	 */
	.macro	v7_ttb_setup, zero, ttbr0l, ttbr0h, ttbr1, tmp
	mcr	p15, 0, \zero, c2, c0, 2	@ TTB control register
        /*** @Iamroot: 2016/09/24
        * TTBCR을 0으로 Set(초기화)
        @Iamroot 2016/09/24***/
	ALT_SMP(orr	\ttbr0l, \ttbr0l, #TTB_FLAGS_SMP)
	ALT_UP(orr	\ttbr0l, \ttbr0l, #TTB_FLAGS_UP)
	ALT_SMP(orr	\ttbr1, \ttbr1, #TTB_FLAGS_SMP)
	ALT_UP(orr	\ttbr1, \ttbr1, #TTB_FLAGS_UP)
        /*** @Iamroot: 2016/09/24
        * page entry table의 크기 정책을 Setting(p.1728 참고) 
        * #TTB_FLAGS_SMP : TTB_IRGN_WBWA|TTB_S|TTB_NOS|TTB_RGN_OC_WBWA 
        * TTB_IRGN_WBWA : inner cache 정책을 어떻게 할지(write back write allocate)
        * TTB_S         : sharable 비트를 세팅  
        * TTB_NOS       : not outer sharable bit -> 0이면 outer 1이면 inner sharable
        * TTB_RGN_OC_WBWA : outer cache정책
        * write through : 데이터를 쓰면 cache의 내용이 변경되면서 main memory도 변경 
        * http://jake.dothome.co.kr/cache1/ 참고 (write through.....)
        @Iamroot 2016/09/24***/
	mcr	p15, 0, \ttbr1, c2, c0, 1	@ load TTB1
        /*** @Iamroot: 2016/09/24
        * TTB 시작주소(\ttbr1)에 TTB_FLASGS_SMP를 or연산후 TTB1에 삽입 
          @Iamroot 2016/09/24***/
	.endm

	/*   AT
	 *  TFR   EV X F   I D LR    S
	 * .EEE ..EE PUI. .T.T 4RVI ZWRS BLDP WCAM
	 * rxxx rrxx xxx0 0101 xxxx xxxx x111 xxxx < forced
	 *   01    0 110       0011 1100 .111 1101 < we want
	 */
	.align	2
	.type	v7_crval, #object
v7_crval:
	crval	clear=0x2120c302, mmuset=0x10c03c7d, ucset=0x00c01c7c
	/*@Iamroot
	 * config_mmu가 set되어있으면 clear와 mmuset를 사용하고 안되어 있으면 clear와 ucset를 사용함
 	 * 예를 들어 raspberry pi2에서는 config_mmu가 set되어있기 때문에
	 * clear와 mmuset를 참고한다.
 	 */

