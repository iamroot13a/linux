/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/v7m.h>

#include "efi-header.S"

 AR_CLASS(	.arch	armv7-a	)
 M_CLASS(	.arch	armv7-m	)

/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG

#if defined(CONFIG_DEBUG_ICEDCC)

#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c0, c5, 0
		.endm
#elif defined(CONFIG_CPU_XSCALE)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0
		.endm
#else
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else

#include CONFIG_DEBUG_LL_INCLUDE

		.macro	writeb,	ch, rb
		senduart \ch, \rb
		.endm

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3
#else
		add	\rb, \rb, #0x00010000	@ Ser1
#endif
		.endm
#else
		.macro	loadsp,	rb, tmp
		addruart \rb, \tmp
		.endm
#endif
#endif
#endif

		.macro	kputc,val
		mov	r0, \val
		bl	putc
		.endm

		.macro	kphex,val,len
		mov	r0, \val
		mov	r1, #\len
		bl	phex
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'
		kphex	r6, 8		/* processor id */
		kputc	#':'
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */
		kputc	#'\n'
		mov	r0, r4
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm

		.section ".start", #alloc, #execinstr
/*** @iamroot   20160618  스터디 시작
  
  섹션정의부분 : .section name // .start 섹션 정의
   
    #alloc : gas directives flag //  elf영역에서 메모리에 올린다고 정의

    - elf (Executable and Linkable Format) : 컴파일후 아웃풋 파일 실행 파일, 목적 파일, 공유 라이브러리 그리고 코어 덤프를 위한 리눅스 표준 파일 형식
    -코어덤프 : 프로그램 비정상 종료시 생성되는 파일로 디버깅을 통해 비정상종료 원인을 파악하는데 사용됨.  프로그램 카운터와 스택 포인터, 메모리 관리 정보, 기타 프로세서와 운영 체제 플래그 및 정보 등을 포함한 프로세서 레지스터같은 프로그램 상태의 중요 부분들이 대개 동시에 덤프됨.

    #execinstr : gas directives flag // 실행 가능한 영역으로 정의 

 ***/


/*
 * sort out different calling conventions
 */
		.align
/*** @iamroot

  메모리 정렬 명령어
  default : 2^2 = 4byte = 32bit 메모리로 정렬시켜
  메모리 읽는 속도를 높임 (32bit arm 머신이므로 한 사이클에 하나의 데이터를 읽을수 있음)
 
 ***/


		/*
		 * Always enter in ARM state for CPUs that support the ARM ISA.
		 * As of today (2014) that's exactly the members of the A and R
		 * classes.
		 */
 AR_CLASS(	.arm	)
/*** @iamroot
 
  AR_CLASS 매크로를 통해 CONFIG_CPU_V7M 가 정의 되어 있으면 .arm 무시 정의되어 있지 않으면 .arm 실행. CONFIG_CPU_V7M 같이 M 시리즈는 정의되어있지 않은 것으로 한다.

  .arm : gas directives  .code32 로 실행

  default 도 arm 이지만 명시적으로 적어두는 코드
 
 ***/

    /* 부트로더 제외 시작점 */
start: /** @iamroot : start 라벨 설정 **/
		.type	start,#function 

/** @iamroot 심볼 타입을 함수로 설정 (funciton, object)
arm에서는 @가 주석이기 때문에 #으로 타입 설정**/

		.rept	7
		__nop  /** @iamroot nop 매크로 라즈베리파이2에서는 EFI부팅을 사용하지 않기때문에 mov r0, r0로 대체 됨 **/
		.endr

/** @iamroot __nop 를 7번 반복 __nop  : 4byte X 7 = 28 byte + 아래 mov r0, r0  포함 32byte = 0x20
 이유? 여러가지 부트로더 중 하나의 부트로더가 0x20 에서 실행하지 않으면 에러가 발생하기 때문에 의미없는 코드 추가
 **/

   ARM(		mov	r0, r0		) /** @iamroot r0 레지스터를 r0 레지스터로 복사한다 이유??? thumb 인스트럭션과 arm 인스트럭션을 혼용할 때 arm 인스트럭션의 align 맞추기로 활용 **/
   ARM(		b	1f		) /** @iamroot 레이블 1 로분기 f : 1이라는 레이블은 많기 때문에 바로 다음에 가까운 1레이블로 분기한다는 의미 1b의 경우 위에서 찾으라는 의미 **/
 THUMB(		badr	r12, 1f		)
 THUMB(		bx	r12		)

		.word	_magic_sig	@ Magic numbers to help the loader
		.word	_magic_start	@ absolute load/run zImage address
		.word	_magic_end	@ zImage end address
		.word	0x04030201	@ endianness flag
	/** @iamroot **/

 THUMB(		.thumb			)
1:		__EFI_HEADER /** @iamroot EFI_HEADER 매크로로 이동**/

 ARM_BE8(	setend	be		)	@ go BE8 if compiled for BE8 /**  @iamroot 빅엔디안을 사용할때 사용되는 코드 
                                                              setend : 엔디안 설정 명령어                               be : setend의 플래그로 빅엔디안 사용
    le : 리틀엔디안 사용                                      **/
 AR_CLASS(	mrs	r9, cpsr	)

/** @iamroot 
 cpsr 데이터를 r9 레지스터에 저장
 **/

#ifdef CONFIG_ARM_VIRT_EXT

    /** @iamroot 하이퍼바이저 모드로 커널 진입 **/
		bl	__hyp_stub_install	@ get into SVC mode, reversibly 
        /** bl명령어의 경우 r14 레지스터(lr)에 다음 실행할 명령어의 주소를 넣어놓고 분기 **/
#endif
		mov	r7, r1			@ save architecture ID
		mov	r8, r2			@ save atags pointer
		/** @iamroot  하드웨어 적으로 기본적인 레지스터 값이 셋팅되어 있다.
		u-boot(부트로더)가 부트 데이터의 물리주소를 r2에 저장하여 커널로 설정정보를 넘겨준다.  
		r0: 0
		r1: architecture ID (machine type number)
		r2: tagged list 의 물리주소 값(혹은 Device Tree Block)
		tagged list: Device Driver 를 표현하는 데이터 구조.
		DTB(Device Tree Block): 하드웨어를 표현하는 트리형태의 데이터 구조체.   운영체제가 하드웨어를 이해할 수 있도록 작성된다. 이 구조체의 정보를 보고 어떤 디바이스인지 알아내고 메모리 어디에 매핑되어 있는지 판단한다. 다양한 하드웨어를 지원해야할 요구를 해결하기 위해 만들어 졌다. Device Driver 에 접근하기위한 방식. Tagged List 에 비해 확장성이 크다.
		**/

#ifndef CONFIG_CPU_V7M
		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 */
		 /** @iamroot Angle: 부트로더의 한 종류. **/

		mrs	r2, cpsr		@ get current mode
		tst	r2, #3			@ not user?
		/** @iamroot tst: And 연산하여 0이면 Z플래그를 set한다. Z(1) **/
		bne	not_angel  
		/** @iamroot bne: Z플래그가 z(0)일 경우 분기 **/
		/** @iamroot User-mode 는 cpsr의 하위 5비트가 10000 이고 나머지 모드는 하위 두 비트중 하나가 1이기 때문에 하위 두 비트를 비교하여 User-mode 인지 판단한다. 따라서 Angel 부트로더일 경우 User 모드로 실행되기 때문에 Z플래그가 set 되어 있고,  분기하지 않는다. **/
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB
not_angel:
		/** @iamroot User 모드도 아니고 SVC 모드도 아닐경우 SVC 모드로 실행되는 것을 보장하기 위해 실행 **/
		safe_svcmode_maskall r0
		msr	spsr_cxsf, r9		@ Save the CPU boot mode in
						@ SPSR
		/** @iamroot 
			spsr_cxsf: google docs 참조 
			http://egloos.zum.com/recipes/v/5033184
		**/
#endif
		/*
		 * Note that some cache flushing and other stuff may
		 * be needed here - is there an Angel SWI call for this?
		 */

		/*
		 * some architecture specific code can be inserted
		 * by the linker here, but it should preserve r7, r8, and r9.
		 */

		.text   /** @iamroot start라는 큰 레이블 안에서 내부의 작은 섹션을 나누어 레이블 처럼 사용 할수 있도록 하는 gas directives 명령
                 사용법 .text 하위섹션이름    섹션이름이 생략되면 0로 셋됨 **/

#ifdef CONFIG_AUTO_ZRELADDR   /** @iamroot zImage로 생성 할 것인가? **/
		/*
		 * Find the start of physical memory.  As we are executing
		 * without the MMU on, we are in the physical address space.
		 * We just need to get rid of any offset by aligning the
		 * address.
		 *
		 * This alignment is a balance between the requirements of
		 * different platforms - we have chosen 128MB to allow
		 * platforms which align the start of their physical memory
		 * to 128MB to use this feature, while allowing the zImage
		 * to be placed within the first 128MB of memory on other
		 * platforms.  Increasing the alignment means we place
		 * stricter alignment requirements on the start of physical
		 * memory, but relaxing it means that we break people who
		 * are already placing their zImage in (eg) the top 64MB
		 * of this range.
		 */
		mov	r4, pc
		and	r4, r4, #0xf8000000
		/* Determine final kernel image address. */
		add	r4, r4, #TEXT_OFFSET
#else
		ldr	r4, =zreladdr  /** @iamroot zreladdr 는 압축해제된 커널이 쓰여질 주소 그리고 최종적으로 실행될 주소를 가리킨다. ??? 하드웨어에 맞춰서 주소가 바뀜  "=" 뒤에 레이블이 나와서 주소를 의미함??  **/
#endif

		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc || r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB.
		 */
		mov	r0, pc              /** @iamroot  현재 프로그램 카운터를 r0로 복사 **/
		cmp	r0, r4          /** @iamroot 현재 pc주소와 압축해제된 커널의 시작위치를 비교  **/
		ldrcc	r0, LC0+32   /** pc주소가 커널주소보다 작다면 PTE영역이 침범 될수 있으므로 LC0 + 32 // LC0 + 32  =  커널 이미지 크기 + PTE 크기 (16K) + DTB의 최대사이즈 (1M)  **/
		addcc	r0, r0, pc   /** @iamroot 현재위치에서 위에 로드한 크기를 더하여 보호해야할 영역을 확보  **/
		cmpcc	r4, r0  /** @iamroot r4와 비교하여 보호 할 영역의 확보 가능한지 비교 r4가 더 작다면 PTE영역이 보호할 영역을 침범하게 되므로 캐시온을 보류하고 r4에 1를 셋하여 보류된 사실을 전달함// r4의 1셋값을 기준으로 추후 캐시온을 하기 위하여  **/
		orrcc	r4, r4, #1		@ remember we skipped cache_on
		blcs	cache_on    /** 캐시온 분기코드 **/

restart:	adr	r0, LC0	  /* iamroot LC0의 주소를 r0에 가져옴 */
		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}  /* iamroot LC0 에서 순차적으로 값을 읽어와 레지스터에 저장. 자세한 설명은 아래 주석 참조  */
		ldr	sp, [r0, #28]  /* @iamroot r0를 28Byte 증가시킨 주소에서 읽어와 sp 주소에서 읽어와 sp에 저장. r0+28 =  .L_user_stack_end */

		/* iamroot 
		 * r0는 LC0가 메모리에 로드된주소, r1은 빌드시  LC0의 메모리 주소
		 * delta offset = r0 - r1
		 * delta offset을 활용하여 실 메모리 주소로 보정한다.
		 */
  		/* iamroot
		 * compressed 커널에서 data영역의 끝 주소를 의미한다.
		 */

		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */ 
		sub	r0, r0, r1		@ calculate the delta offset
		add	r6, r6, r0		@ _edata
		add	r10, r10, r0		@ inflated kernel size location

		/* iamroot 
		 * piggy.S의 piggy_data의 끝 4byte에 kernel size가 들어있는데
		 * 이 size를 endian에 관계없이 강제로 little endian 형식으로 
		 * 읽어온다.
		 */

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		ldrb	r9, [r10, #0]
		ldrb	lr, [r10, #1]
		orr	r9, r9, lr, lsl #8
		ldrb	lr, [r10, #2]
		ldrb	r10, [r10, #3]
		orr	r9, r9, lr, lsl #16
		orr	r9, r9, r10, lsl #24
 
#ifndef CONFIG_ZBOOT_ROM 
 /* iamroot 
  * 일반적인 경우 RAM에 로드후 실행하여 Decompress한다. 
  * 정의되어 있는 경우 ROM/Flash에서 실행하여 RAM으로 Decompress한다.
  * ROM에서 실행하는것이 매우느리기 때문에 ??? 
  */
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0  /* iamroot sp에 delta offset을 더하여 주소갑을 보정해줌   */
		add	r10, sp, #0x10000  /* iamroot  r10 이 스택을 가리키고 스택 사이즈를 0x10000으로. 압축해제를 위해 공간을 할당해 준다.*/
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6
#endif
		/* iamroot r5를 dtb size를 나타내는 레지스터로 사용하며 0로 초기화한다. */
		mov	r5, #0			@ init dtb size to 0
#ifdef CONFIG_ARM_APPENDED_DTB
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end줌
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, includin조g  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		/* iamroot 
		 * _edata의 처음 부분을 읽어 Magic Number를 비교한다.
		 * Magic이 DTB의 Magic인지 확인한다.
		 * linux/Documentation/devicetree/booting-without-of.txt 의 line 359 참조
		 */
		ldr	lr, [r6, #0]
#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
#else
		ldr	r1, =0xd00dfeed
#endif
		cmp	lr, r1
		bne	dtb_check_done		@ not found

#ifdef CONFIG_ARM_ATAG_DTB_COMPAT
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here. No GOT fixup has occurred
		 * yet, but none of the code we're about to call uses any
		 * global variable.
		*/

		/* Get the initial DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif
		/* 50% DTB growth should be good enough */
		add	r5, r5, r5, lsr #1
		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7
		/* clamp to 32KB min and 1MB max */
		cmp	r5, #(1 << 15)
		movlo	r5, #(1 << 15)
		cmp	r5, #(1 << 20)
		movhi	r5, #(1 << 20)
		/* temporarily relocate the stack past the DTB work space */
		add	sp, sp, r5

		stmfd	sp!, {r0-r3, ip, lr}
		mov	r0, r8
		mov	r1, r6
		mov	r2, r5
		bl	atags_to_fdt

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		cmp	r0, #1
		sub	r0, r4, #TEXT_OFFSET
		bic	r0, r0, #1
		add	r0, r0, #0x100
		mov	r1, r6
		mov	r2, r5
		bleq	atags_to_fdt

		ldmfd	sp!, {r0-r3, ip, lr}
		sub	sp, sp, r5
#endif

		mov	r8, r6			@ use the appended device tree

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size
		adr	r1, wont_overwrite
		sub	r1, r6, r1
		subs	r1, r5, r1
		addhi	r9, r9, r1

		/* Get the current DTB size */
		ldr	r5, [r6, #4]
#ifndef __ARMEB__
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif

		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7

		/* relocate some pointers past the appended dtb */
		add	r6, r6, r5
		add	r10, r10, r5
		add	sp, sp, r5
dtb_check_done:
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384
		cmp	r4, r10
		bhs	wont_overwrite
		/* iamroot PTE가 overwrite 되는 것을 방지하기위해 크기비교 */
		add	r10, r4, r9
		adr	r9, wont_overwrite
		cmp	r10, r9
		bls	wont_overwrite
		/* iamroot wont_overwrite 가 overwrite 되는 것을 방지하기위해 크기 비교 */
		/* iamroot 
		 * 현재 커널의 위아래 메모리 영역을 확인한다. 
		 * Overwrite 된다고 판단된경우 아래 코드를 실행하게 된다.
		 */ 

/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		/* iamroot
		 * Compressed kernel 코드를 decompressed kernel 위로 옮기기 위해
		 * 현재 decompressed kernel의 끝에서 256 byte 만큼 더해준다.
		 * 또 32바이트씩 copy하면서 overwrite될 가능성과 cache flush code에서 
		 * 문제가 발생할 확률이 있어서 relocation code size 만큼 더해준다. 
		 * 그다음 256 byte boundary로 맞춰준다.
		 */
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
		bic	r10, r10, #255

		/* Get start of code we want to copy and align it down. */
		/* iamroot 
		 * 10000(2) 는 메모리주소값 관점으로 보면 32byte 단위.
		 * align을 하는 이유는 cache의 입출력 단위가 32byte이기 때문이다.(속도가 빠르다)
		 */
		adr	r5, restart
		bic	r5, r5, #31	/* iamroot #31 = 0x1f = 00011111 */

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE
		bne	1f

		bl	__hyp_get_vectors
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif
		sub	r9, r6, r5		@ size to copy
		add	r9, r9, #31		@ rounded up to a multiple
		bic	r9, r9, #31		@ ... of 32 bytes
		/* iamroot 현재r9는 restart 부터 _edata 까지의 크기를 32byte로 align 한 size 값. */
		add	r6, r9, r5
		/* iamroot r6는 복사를 시작할 source 주소가 된다. */
		add	r9, r9, r10
		/* iamroot r9은 복사할 destination 주소가 된다. */

		/* iamroot
		 * source(r6 = _edata)에서 4byte씩 주소값을 감소시키며 8개의 값을 읽어온다.
		 * 하나의 ldmdb 명령으로 총 32 byte를읽어 {r0 - r3, r10 - r12, lr} 에 저장한다. 
		 * {r0 - r3, r10 - r12, lr} 레지스터에 있는 32byte 값을 
		 * 다시 destination(r9)이 가리키는 주소값에 쓴다.
		 */
1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}
		cmp	r6, r5
		stmdb	r9!, {r0 - r3, r10 - r12, lr}
		bhi	1b

		/* Preserve offset to relocated code. */
		sub	r6, r9, r6 /* iamroot 현재 실행중인 코드에서 복사한 코드로의 offset 
				      정확하게 다음 instruction으로 옮겨가기 위해 사용한다.*/

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6
#endif

		bl	cache_clean_flush

		/* iamroot
		 * 복사된 코드의 restart 실행
		 */
		badr	r0, restart
		add	r0, r0, r6
		mov	pc, r0

wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
 		/* iamroot 
		 * 
		 */
		orrs	r1, r0, r5  
		beq	not_relocated

		add	r11, r11, r0
		add	r12, r12, r0

#ifndef CONFIG_ZBOOT_ROM
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0
		add	r3, r3, r0

		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		add	r1, r1, r0		@ This fixes up C references
		cmp	r1, r2			@ if entry >= bss_start &&
		cmphs	r3, r1			@       bss_end > entry
		addhi	r1, r1, r5		@    entry += dtb size
		str	r1, [r11], #4		@ next entry
		cmp	r11, r12
		blo	1b

		/* bump our bss pointers too */
		add	r2, r2, r5
		add	r3, r3, r5

#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1
		bic	r4, r4, #1
		blne	cache_on

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4
		mov	r1, sp			@ malloc space above stack
		add	r2, sp, #0x10000	@ 64k max
		mov	r3, r7
		bl	decompress_kernel
		bl	cache_clean_flush
		bl	cache_off
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer

#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		bne	__enter_kernel		@ boot kernel directly

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel
#endif

		.align	2
		.type	LC0, #object
LC0:		.word	LC0			@ r1
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		.word	_got_start		@ r11
		.word	_got_end		@ ip
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024   /** _end - restart ( 커널 이미지 크기) + PTE 크기 (16K) + DTB의 최대사이즈 (1M)  **/
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on. // 인스트럭트 and 데이터 캐시
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_on:	mov	r3, #8			@ cache_on function
		b	call_cache_fn

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif


        /* @iamroot
         * r4 : kernel 시작 주소가 저장되어있음
         * __setup_mmu:	sub	r3, r4, #16384  r4 에서 16K를 빼서 r3에 저장
         * bic r3, r3, #0xff     하위 8비트를 비움
         * bic r3, r3, #0x3f00   8 ~ 13 까지 비트를 비움
         * 
         * 0 ~ 13 까지 비트를 비우게 되면  16K 의 배수가 되어 페이지 테이블의
         * 엔트리 주소에 맞춰 정렬할수 있다
         *
         * ?? 비트클리어를 왜 두번 나누어서 하는가?
         * arm 에서 명령어의 크기의 제약때문에.. 
         * 두번째 operand의 경우 12bit의 제약을 가진다. 따라서 2의12승의 경우
         * 0 ~ 4095 까지의 수만 표현가능하다. 이 제약을 해결하기위해 arm에서는
         * 상위 4비트를 shift rotate right로 하위 8비트를 값으로 지정하고
         * 로테이트값에 2를 곱하여 32비트를 모두 접근 가능하도록 설계되었다.
         * (양수만 가능)
         */
__setup_mmu:	sub	r3, r4, #16384		@ Page directory size
		bic	r3, r3, #0xff		@ Align the pointer
		bic	r3, r3, #0x3f00    
/*
 * Initialise the page tables, turning on the cacheable and bufferable
 * bits for the RAM area only.
 */
    /* @iamroot
     *  페이지 디렉토리의 시작 주소에서 메모리의 사이즈만큼
     *  더하여 메모리를 확보
     * 	mov	r0, r3          
	 *	mov	r9, r0, lsr #18     하위비트를 클리어시킴
	 *	mov	r9, r9, lsl #18		@ start of RAM  4G의 가상메모리의 시작점과 물리메모리를 매핑
	 *	add	r10, r9, #0x10000000	  램의 토탈사이즈 // 256MB
	 *	mov	r1, #0x12		XN 과 section 으로 선언함. Domain을 포함한 [31:8] 부분은
	 					0로 초기화 됨.
	 *	orr	r1, r1, #3 << 10	AP[1:0]영역에 11 셋  (access permition)
     *                          메모리의 Full access 가능 ref : arm 메뉴얼 p1358
	 *	add	r2, r3, #16384      페이지 테이블의 끝
     */
		mov	r0, r3
		mov	r9, r0, lsr #18
		mov	r9, r9, lsl #18		@ start of RAM
		add	r10, r9, #0x10000000	@ a reasonable RAM size
		mov	r1, #0x12		@ XN|U + section mapping
		orr	r1, r1, #3 << 10	@ AP=11
		add	r2, r3, #16384
/* @iamroot 
 * 1:		cmp	r1, r9      램과 r1 XN + section 과 비교			
 *		    cmphs	r10, r1	    조건부연산 hs : cs와 같은뜻 carry set일때 실행
 *                              r1 - r9 >= 0 일때 cmphs r10, r1 실행
 *                               r10 - r1 >=0 일때 carry set
 *		    bic	r1, r1, #0x1c		XN 과 Cache , Buffer 를 0으로 초기화 
 *		    orrlo	r1, r1, #0x10  조건부연산 lo : cc 
 *                                  r1 가 램 영역안에 없을때 수행됨
 *                                  의미 : XN 비트를 1로 셋      
 *		    orrhs	r1, r1, r6      r6 : 0x0e   r1 에 C+B+ section비트를 셋  	
 *		    str	r1, [r0], #4        PTE의 시작주소에서 4byte씩 증가시키면서 저장
 *		    add	r1, r1, #1048576    섹션 베이스 어드레스를 1씩 증가(1M)
 *		    teq	r0, r2              teq : xor 플래그만 바꿔줌  r0 와 r2과 같을때
 *                                  0이 나옴 Z플래그가 1로 셋  // r2는 끝점
 *		    bne	1b               r0와 r2과 같지 않으면 반복 (4G까지 4096번반복)
 */
1:		cmp	r1, r9			@ if virt > start of RAM
		cmphs	r10, r1			@   && end of RAM > virt
		bic	r1, r1, #0x1c		@ clear XN|U + C + B
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
		orrhs	r1, r1, r6		@ set RAM section settings
		str	r1, [r0], #4		@ 1:1 mapping
		add	r1, r1, #1048576   @ 0x00100000
		teq	r0, r2
		bne	1b
/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */

        /* @iamroot
		* orr	r1, r6, #0x04	 라이트백일경우에도 Buffer셋 하기 위하여
		* orr	r1, r1, #3 << 10  AP 셋 = full access
		* mov	r2, pc              r2 에 현재 프로그램카운터 로드
		* mov	r2, r2, lsr #20     현재수행하고 있는 주소의  섹션베이스어드레스
        *                           주소를 구함
	    * orr	r1, r1, r2, lsl #20
		* add	r0, r3, r2, lsl #2  상대주소를 구하기위해 4를 곱함 ( << 2 = * 4 )
		*/
        orr	r1, r6, #0x04		@ ensure B is set for this
		orr	r1, r1, #3 << 10
		mov	r2, pc
		mov	r2, r2, lsr #20
		orr	r1, r1, r2, lsl #20
		add	r0, r3, r2, lsl #2
        /*
		 * str	r1, [r0], #4       r1 값을 r0가 가지고 있는 주소에 쓰고
         *                         r0의 주소값을 4증가시킴   
		 * add	r1, r1, #1048576   r1에 1M를 더함     
		 * str	r1, [r0]           r1 값을 r0가 가리키는 주소에 씀
		 * mov	pc, lr             return
         */
		str	r1, [r0], #4
		add	r1, r1, #1048576
		str	r1, [r0]
		mov	pc, lr
ENDPROC(__setup_mmu)

@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

        /** @iamroot mmu 캐시온코드 
          **/
__armv7_mmu_cache_on:
		mov	r12, lr 
#ifdef CONFIG_MMU
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0
/* @iamroot  mrc ARM 레퍼런스 찾는법
 * 0  :  OPcode 1
 * r11 : arm 레지스터 
 * c0 : CRn
 * c1 : CRm
 * 4  : OPcode 2  // 생략가능
 * 결과값 : ID_MMFR0, Memory Model Feature Register 0
 */
		tst	r11, #0xf		@ VMSA :  버츄얼 메모리 시스템 아키텍쳐  지원하지 않으면 0000 bit
		movne	r6, #CB_BITS | 0x02	@ !XN 
        /* @iamroot
        * !execute never  : r6에 0x0E 값이들어감
        * VMSA를 지원하면.. 조건부연산 ne  Zero 플래그가 0 (z) 일때 실행
        * !!! 0x02 가 XN 관련 비트인것으로 추정됨
        * CB_BITS는 DCACHE 라이트쓰루 or 라이트백 인지에 따라 결정됨
        * ? 라이트쓰루 : 캐시변경과함께 메모리반영
        * ? 라이트백 : 캐시 변경후 메모리 반영x
        */
		blne	__setup_mmu  @ VMSA를 지원할때 __setup_mmu  진입
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
/* iamroot
* 		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
*      결과값 : CP15DSB, Data Synchronization Barrier operation
*       데이터 동기화?  캐시 -> 메모리
*	
*		tst r11, #0xf		VMSA 지원하지 않으면 0000bit
*		mcrne	p15, 0, r0, c8, c7, 0	 ne 조건연산자 이므로 Z플래그가 0일때 실행 -> VMSA를 지원하면 실행
*		TLB를 초기화 해주는 코드. 초기화 이유 : TLB에 초기화 되어 있지 않으면 예측할수 없는 동작이 가능함
*		TLB란?	Translation Lookaside Buffer
*					PTE들을 위한 특별한 고속의 Cache : memory cache와 동일기능을 수행하며 
*					가장 최근에 사용되었던 PTE들을 저장한다.
*					가상메모리와 물리메모리를 매핑하여 빠르게 엑세스 가능(TLB가 없다면 두번 엑세스해야함)
*/	
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
/* iamroot
*		mrc	p15, 0, r0, c1, c0, 0	r0레지스터로 시스템컨트롤 레지스터의 데이터를 가져옴
*		bic	r0, r0, #1 << 28	TRE 비트를 0으로 셋 (TEX REMAP DISABLE)
*								TEX REMAP 은 cache able 정책을 유연하게 사용할수 있다.
*								하지만 현재 사용하지 않는다..... 불안정
*		orr	r0, r0, #0x5000		I - RR 비트를 1로 셋// I-캐시 사용 및  RR 캐시정책을 사용한다
*								RR 이 캐시정책에 많이 쓰이는 이유 ?
*								현재 RISC 프로세서에서 경험적으로 RR이 가장 효율적이다.
*		orr	r0, r0, #0x003c		5bit : CP15BEN  cache barrier 사용
*								3:4 bit : Reserved, RAO/SBOP.
*								Read-As-One, Should-Be-One-or-Preserved on writes.
*								2bit : cache enable // unified cache : I or D 캐시로 사용되는 통합캐시
*								
*								정렬을 하면 최적의 성능을 낼수 있기때문에 과거 임베디드 시스템의 경우
*								비정렬 처리를 허용하지 않았지만 최근 임베디드 시스템의 경우
*								비정렬 처리를 해도 충분한 성능을 가지고 있기때문에 허용되게 되었다.
*		bic	r0, r0, #2			A bit를 클리어 : 정렬 체크 사용 안함
*								정렬이 되어 있지 않더라도 비정렬 처리 허용
*
*		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
*								U비트가 셋되있을때 비정렬 처리 허용....
*								반면에 U비트가 0일때는rotated aligned 한다?????????`
*
*/
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x003c		@ write buffer
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)

/* iamroot
 ARM_BE8(	orr	r0, r0, #1 << 25 )	little endian 으로 가정하므로 수행 안됨.
		mrcne   p15, 0, r6, c2, c0, 2   r6 레지스터에 TTBCR 을 읽어옴
		orrne	r0, r0, #1		M bit. PL1과 PL0의 stage 1 MMU를 enable한다
						PL(Privilege Level): Non-secure 상태일때 ARMv7에는
						0, 1, 2 세가지 권한이 존재한다. 0는 유저 프로그램, 
						1은 통상 운영체제 프로그램, 2는 하이퍼바이저 레벨이다.
						stage 1: VA to PA or IPA
							 가상주소를 물리주소로 변환하는 단계. 만약 OS가
							 Guest일 경우 IPA로 변환된다.
						stage 2: IPA to PA
							 하이퍼바이저 모드일 경우 IPA를 실제 PA로 변환
							 시켜주는 단계.
		movne	r1, #0xfffffffd		@ domain 0 = client
		bic     r6, r6, #1 << 31        EAE bit. TTBCR을 short/long중 어떤 포맷을 사용할지 결정
						한다. 0: short, 1: long
		bic     r6, r6, #3 << 0         TTBR0 만 쓰도록한다. ??? #7 이어야 하는것 아닌가
		mcrne	p15, 0, r3, c2, c0, 0	PTE시작주소(r3)를 TTBR0에 로드
		mcrne	p15, 0, r1, c3, c0, 0 	DACR(Domain Access Control Register)에 0xfffffffd 
						값을 넣는다. DACR은 2bit로 하나의 메모리 도메인을 표현하며
						총 16개의 도메인을 가진다. 각 도메인의 값은 메모리 권한을
						나타낸다.
						00: No Access - 모두 접근 불가
						01: Client    - PTE의 AP값을 따른다
						10: Reserved
						11: Manager   - 권한 검사 없이 모두 허용한다. (모두 접근)
						따라서 D0의 권한을 Client로 설정하며 D1~15는 Manager로
						설정된다.
		mcrne   p15, 0, r6, c2, c0, 2   r6에 설정한 값을 TTBCR로 로드
*/
#ifdef CONFIG_MMU
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
		orrne	r0, r0, #1		@ MMU enabled
		movne	r1, #0xfffffffd		@ domain 0 = client
		bic     r6, r6, #1 << 31        @ 32-bit translation system
		bic     r6, r6, #3 << 0         @ use only ttbr0
		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
#endif

/* iamroot
		mcr	p15, 0, r0, c7, c5, 4	ISB(Instruction Syncronization Barrier):
						전후 Instruction에 의존성이 있을 경우나 최적화로 인해
						Instruction의 순서가 변경되었을 경우 동기화를 위해
						CPU pipeline을 flush하여 이전 코드들이 완료되었음을
						보장한다. cp15 c7 명령은 deprecated 되었고 ISB라는(혹은 
						DMB, DSB등) 전용 Instruction이 지원된다. 하지만 기존
						버전과의 호환성을 위해 사용했다고 commiter가 말했다.
						아래 명령을 위해 사용됨
		mcr	p15, 0, r0, c1, c0, 0	MMU enable
		mrc	p15, 0, r0, c1, c0, 0	cp15를 변경했을 경우 erratum E7 문제(?)에 의해서
						CPU가 오작동 할 수 있다. 이 문제를 해결하기 위해 
						일종의 Interval(CPWAIT)을 두려고 두 Instruction을 사용한다.
						link: http://www.marvell.com/application-processors/pxa-family/assets/pxa_27x_spec_update.pdf 의 E7 부분.
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12
*/
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12
/* iamroot
	__armv7_mmu_cache_on을 통해 결과적으로 수정된 SCTRL(r0) 레지스터 값
	TRE 비트를 0으로 셋
	I - RR 비트를 1로 셋
	5bit : CP15BEN
	3:4 bit : Reserved,
	2bit : cache enable 
	A bit를 클리어 : 정렬 체크 사용 안함
	U bit 1로 set
	M bit 1로 set
*/
__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted
 *  r2  = corrupted
 *  r3  = block offset
 *  r9  = corrupted
 *  r12 = corrupted
 */

call_cache_fn:	adr	r12, proc_types
#ifdef CONFIG_CPU_CP15
        /* @iamroot CP15 : 시스템 컨트롤을 목적을 가진 코프로세서
         *  Main ID 레지스터를 읽어와서 r9 레지스터에 복사
         */
		mrc	p15, 0, r9, c0, c0	@ get processor ID
#elif defined(CONFIG_CPU_V7M)
		/*
		 * On v7-M the processor id is located in the V7M_SCB_CPUID
		 * register, but as cache handling is IMPLEMENTATION DEFINED on
		 * v7-M (if existant at all) we just return early here.
		 * If V7M_SCB_CPUID were used the cpu ID functions (i.e.
		 * __armv7_mmu_cache_{on,off,flush}) would be selected which
		 * use cp15 registers that are not implemented on v7-M.
		 */
		bx	lr
#else
		ldr	r9, =CONFIG_PROCESSOR_ID
#endif

/* @iamroot
* proc_types 주소에서 상대주소 0 와 4를더해 value와 mask의 값을 r9에 저장되어 있는 프로세서 ID와 비교하여 알맞은 프로세서를 찾는 루틴  
*/

1:		ldr	r1, [r12, #0]		@ get value
		ldr	r2, [r12, #4]		@ get mask
		eor	r1, r1, r9		@ (real ^ match)
		tst	r1, r2			@       & mask
 ARM(		addeq	pc, r12, r3		) @ call cache function
 THUMB(		addeq	r12, r3			)
 THUMB(		moveq	pc, r12			) @ call cache function
		add	r12, r12, #PROC_ENTRY_SIZE
		b	1b

/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush

		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
        /** @iamroot 
         * armv7이라고 가정
         **/
		W(b)	__armv7_mmu_cache_on    
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush

		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r12, lr
		bl	__armv7_mmu_cache_flush
		mov	r0, #0
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5
cache_clean_flush:
		mov	r3, #16
		b	call_cache_fn

__armv4_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		tst	r4, #1
		mcreq	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcreq	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:
		tst	r4, #1
		bne	iflush		/* @Iamroot: mmu가 꺼져있으면 분기 
						 * 재배치하기 전 cache를 지우고 간다? Dcache에 있는 데이터를
						 * 모두 flush한 후 main memory에서 가져오기 위해
						 */
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
								/* @Iamroot: L1 Harvard cache와 비교 */
		mov	r10, #0
		beq	hierarchical
		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
hierarchical:
		/* @Iamroot :
		mcr	p15, 0, r10, c7, c10, 5	 @ Data Memory Barrier: Core사이의 data 상태를 맞춰준다. ISB와 유사
		stmfd	sp!, {r0-r7, r9-r11} @ 
		mrc	p15, 1, r0, c0, c0, 1	@
		ands	r3, r0, #0x7000000	@
		mov	r3, r3, lsr #23		@ 
		beq	finished		@ 
		mov	r10, #0			@ 
		*/
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
		stmfd	sp!, {r0-r7, r9-r11}
		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
		ands	r3, r0, #0x7000000	@ extract loc from clidr
		mov	r3, r3, lsr #23		@ left align loc bit field
		beq	finished		@ if loc is 0, then no need to clean
		mov	r10, #0			@ start clean at cache level 0
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
		and	r1, r1, #7		@ mask of the bits for current cache only
		cmp	r1, #2			@ see what cache we have at this level
		blt	skip			@ skip if no cache, or just i-cache
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
		and	r2, r1, #7		@ extract the length of the cache lines
		add	r2, r2, #4		@ add 4 (line length offset)
		ldr	r4, =0x3ff
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
		clz	r5, r4			@ find bit position of way size increment
		ldr	r7, =0x7fff
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
loop2:
		mov	r9, r4			@ create working copy of max way size
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
		subs	r9, r9, #1		@ decrement the way
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10
		bgt	loop1
finished:
		ldmfd	sp!, {r0-r7, r9-r11}
		mov	r10, #0			@ swith back to cache level 0
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		tst	r4, #1
		movne	pc, lr
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf
		mov	r2, #0
		strb	r2, [r3, r1]
1:		subs	r1, r1, #1
		movmi	r0, r3
		bmi	puts
		and	r2, r0, #15
		mov	r0, r0, lsr #4
		cmp	r2, #10
		addge	r2, r2, #7
		add	r2, r2, #'0'
		strb	r2, [r3, r1]
		b	1b

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1
		teq	r2, #0
		moveq	pc, lr
2:		writeb	r2, r3
		mov	r1, #0x00020000
3:		subs	r1, r1, #1
		bne	3b
		teq	r2, #'\n'
		moveq	r2, #'\r'
		beq	2b
		teq	r0, #0
		bne	1b
		mov	pc, lr
@ putc corrupts {r0, r1, r2, r3}
putc:
		mov	r2, r0
		mov	r0, #0
		loadsp	r3, r1
		b	2b

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
 ARM(		mov	pc, r4		)	@ call kernel
 M_CLASS(	add	r4, r4, #1	)	@ enter in Thumb mode for M class
 THUMB(		bx	r4		)	@ entry point is always ARM for A/R classes

reloc_code_end:

#ifdef CONFIG_EFI_STUB
		.align	2
_start:		.long	start - .

ENTRY(efi_stub_entry)
		@ allocate space on stack for passing current zImage address
		@ and for the EFI stub to return of new entry point of
		@ zImage, as EFI stub may copy the kernel. Pointer address
		@ is passed in r2. r0 and r1 are passed through from the
		@ EFI firmware to efi_entry
		adr	ip, _start
		ldr	r3, [ip]
		add	r3, r3, ip
		stmfd	sp!, {r3, lr}
		mov	r2, sp			@ pass zImage address in r2
		bl	efi_entry

		@ Check for error return from EFI stub. r0 has FDT address
		@ or error code.
		cmn	r0, #1
		beq	efi_load_fail

		@ Preserve return value of efi_entry() in r4
		mov	r4, r0
		bl	cache_clean_flush
		bl	cache_off

		@ Set parameters for booting zImage according to boot protocol
		@ put FDT address in r2, it was returned by efi_entry()
		@ r1 is the machine type, and r0 needs to be 0
		mov	r0, #0
		mov	r1, #0xFFFFFFFF
		mov	r2, r4

		@ Branch to (possibly) relocated zImage that is in [sp]
		ldr	lr, [sp]
		ldr	ip, =start_offset
		add	lr, lr, ip
		mov	pc, lr				@ no mode switch

efi_load_fail:
		@ Return EFI_LOAD_ERROR to EFI firmware on error.
		ldr	r0, =0x80000001
		ldmfd	sp!, {ip, pc}
ENDPROC(efi_stub_entry)
#endif

		.align
		.section ".stack", "aw", %nobits
.L_user_stack:	.space	4096
.L_user_stack_end:
