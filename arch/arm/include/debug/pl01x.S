/* arch/arm/include/debug/pl01x.S
 *
 * Debugging macro include header
 *
 *  Copyright (C) 1994-1999 Russell King
 *  Moved from linux/arch/arm/kernel/debug.S by Ben Dooks
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
*/
#include <linux/amba/serial.h>

#ifdef CONFIG_DEBUG_ZTE_ZX
#undef UART01x_DR
#undef UART01x_FR
#define UART01x_DR     0x04
#define UART01x_FR     0x14
#endif

/*
   Q. UART는 booting시 자동으로 설정값이 세팅되는가?
      세팅된다면 언제 되는가?
 */

#ifdef CONFIG_DEBUG_UART_PHYS
		.macro	addruart, rp, rv, tmp
		ldr	\rp, =CONFIG_DEBUG_UART_PHYS
		ldr	\rv, =CONFIG_DEBUG_UART_VIRT
		.endm
#endif

		.macro	senduart,rd,rx
		strb	\rd, [\rx, #UART01x_DR]  /* [\rx + #0x04] = \rd (1Byte)
						  * Data read or written from the interface
						  */
		.endm

		.macro	waituart,rd,rx
1001:		ldr	\rd, [\rx, #UART01x_FR]
 ARM_BE8(	rev	\rd, \rd )
		tst	\rd, #UART01x_FR_TXFF   /* rd, TXFF 비교*/

		/* TXFF (Transmit FIFO full, UARTFR의비트[5])
		 * UARTLCR_H의 FEN비트의 상태값에 따라 이 플래그의 의미가 달라진다.
		 * FIFO가disabled라면,
	         *	이 플래그는 receive holding register가 empty될 때,SET된다.
		 * FIFO가 enabled라면,
		 *	이 플래그는 transmit FIFO가 full일 때, SET된다.
		 */
		bne	1001b		/* TXFF가 SET이면 FIFO가 비어질 때(not full)까지 무한루프*/
		.endm

		.macro	busyuart,rd,rx
1001:		ldr	\rd, [\rx, #UART01x_FR]	/* FR : Flag register , read only */
 ARM_BE8(	rev	\rd, \rd )
		tst	\rd, #UART01x_FR_BUSY	/* FR_BUSY레지스터가 SET이냐, 아니냐를 보고
						 * 이전의 uart 출력 전송이 완료되었는지 확인
						 */
		bne	1001b
		.endm
