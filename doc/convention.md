# Convention
## Naming
**Variable**
- `entity_attribute`

**Function**
- `prefix_noun_verb`

**pointer**
- pointer `_p`
- double pointer `_pp`
- array `_arr`
- buffer `_buf`
- format `_fmt`
- opaque `_opq`
- string (`static const` string only) `_str`
```c
static const C8 abc_str[] = "abc";
I32 name_arr[10] = {0};
name_arr[0] = 1;

/* Must not use '&' for array address to pointer. E.g., name_arr_p = &name_arr; */
I32 *name_arr_p = name_arr;

I32 **name_arr_pp = &name_arr_p;
I32 *restore_arr = *name_arr_pp;
restore_arr[0] = 1;

C8 name_buf[] = "Buffer";
C8 *name_buf_p = name_buf;
C8 **name_buf_pp = &name_buf_p;

C8 name_fmt[] = "Format %s %d\n";

struct name_st {
   	I32 abc;
};
struct name_st name_st = {0};
name_st.abc = 1;
U8 *name_st_opq_p = (void *) &name_st;
struct name_st *restore_st = (struct name_st *) name_st_opq_p;
restore_st->abc = 2;
```

## Rules
**Must**
- Must not use overflow functions like `strlen()`.
- Must not use `const` in function parameters, except pointer type. E.g., `void func(I32 ro_int, const I32 *ro_ptr);`
- Must use explicit type.
- - `int a = 10;` -> `I32 a = 10;`
- - `unsinged int a = 10;` -> `U32 a = 10;`
- Must memory freed `mem = FAC_NULL;`, and after file diescriptor closed `fd = -1`. E.g., `free(mem); mem = FAC_NULL; if (fd > 0) { close(fd); fd = -1; }`

**Should**
- Should not header pollution.
- Should use `U64` in like `for()`, `while()`.
- Should use unsinged number using `U`. E.g., `if ((U32) cnt < 3U)`, `arr[1U]`
- Should `I32 func_ret = func(); if (func_ret < 0)`, should not `if (func() < 0)`.
- Readonly data should use `static const` instead of `#define`.
- Should use memory free or file descriptor close using `goto out;` and `out` label in function bottom.
- Should use `void` parameter, if no parameters (e.g., `func(void)`).

**May**
- Order for parameters e.g., `func(dst, src, num)`, `func(dst, dst_n, src, src_n)`.
- Order for variables for example:
```c
void func(void) {
    /* static */
    static const C8 abc_str[] = "abc";

    /* require free */
    C8 *ptr = FAC_NULL;

    /* file desciptor */
    I32 fd = -1;

    /* reuse variable */
    I32 ret = 0;

    /* normal variable */
    I32 a = 0;
    /* [logic] <a> */

    struct a_st a_st = {0};
    /* [logic] <a_st> */

    /* [logic] <a_st, a> */
}
```

---

> Authors 2026 Facooya and Fanone Facooya
