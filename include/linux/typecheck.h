#ifndef TYPECHECK_H_INCLUDED
#define TYPECHECK_H_INCLUDED

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#if 0  /* @Iamroot: 2016.11.12 */
    __dummy 와 __dummy2가 자료형이 다를 경우 컴파일시 warning가 발생함
    one operand is a pointer to an object or incomplete type and the other is a pointer to a qualified or unqualified version of void
    typeof => type return
#endif /* @Iamroot  */
/*
 * Check at compile time that 'function' is a certain type, or is a pointer
 * to that type (needs to use typedef for the function type.)
 */
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})

#endif		/* TYPECHECK_H_INCLUDED */
