	.type	initrd_start,#object
	.globl	initrd_start
initrd_start:
	.incbin	INITRD
	.globl	initrd_end
#if 0  /* @Iamroot: 2017.03.25 */
        INITRD : 컴파일 할 때 선언
        컴파일할 경우 INITRD를 사용후 파일을 선언하면 파일이 INITRD에 들어감
#endif /* @Iamroot  */
initrd_end:
