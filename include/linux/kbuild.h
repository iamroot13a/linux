#ifndef __LINUX_KBUILD_H
#define __LINUX_KBUILD_H

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define BLANK() asm volatile("\n->" : : )

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))
/*** @Iamroot: 2016/09/03
  offsetof : str의 mem변수의 오프셋을 구한다 
@Iamroot 2016/09/03***/

#define COMMENT(x) \
	asm volatile("\n->#" x)

#endif
