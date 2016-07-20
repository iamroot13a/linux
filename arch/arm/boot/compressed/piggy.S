	.section .piggydata,#alloc
	.globl	input_data
input_data:
	.incbin	"arch/arm/boot/compressed/piggy_data" /* iamroot 압축된 linux kernel의 바이너리 이미지 */
	.globl	input_data_end
input_data_end:
