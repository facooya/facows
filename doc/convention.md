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
static const char abc_str[] = "abc";
s32 name_arr[10] = {0};
name_arr[0] = 1;

/* Must not use '&' for array address to pointer. E.g., name_arr_p = &name_arr; */
s32 *name_arr_p = name_arr;

s32 **name_arr_pp = &name_arr_p;
s32 *restore_arr = *name_arr_pp;
restore_arr[0] = 1;

char name_buf[] = "Buffer";
char *name_buf_p = name_buf;
char **name_buf_pp = &name_buf_p;

char name_fmt[] = "Format %s %d\n";

struct name_st {
   	s32 abc;
};
struct name_st name_st = {0};
name_st.abc = 1;
u8 *name_st_opq_p = (void *) &name_st;
struct name_st *restore_st = (struct name_st *) name_st_opq_p;
restore_st->abc = 2;
```

## Rules
**Must**
- Must not use overflow functions like `strlen()`.
- Must not use `const` in function parameters, except pointer type. E.g., `void func(s32 ro_int, const s32 *ro_ptr);`
- Must use explicit type.
- - `int a = 10;` -> `s32 a = 10;`
- - `unsinged int a = 10;` -> `u32 a = 10;`
- Must memory freed `mem = NULL;`, and after file diescriptor closed `fd = -1`. E.g., `free(mem); mem = NULL; if (fd > 0) { close(fd); fd = -1; }`

**Should**
- Should not header pollution.
- Should `s32 func_ret = func(); if (func_ret < 0)`, should not `if (func() < 0)`.
- Readonly data should use `static const` instead of `#define`.
- Should use memory free or file descriptor close using `goto out;` and `out` label in function bottom.
- Should use `void` parameter, if no parameters (e.g., `s32 func(void); ret = func();`).

**May**
- Order for parameters e.g., `func(dst, src, num)`, `func(dst, dst_n, src, src_n)`.
- Order for variables for example:
```c
void func(void) {
    /* static */
    static const char abc_str[] = "abc";

    /* require free */
    char *ptr = NULL;

    /* file desciptor */
    s32 fd = -1;

    /* reuse variable */
    s32 ret = 0;

    /* normal variable */
    s32 a = 0;
    /* [logic] <a> */

    struct a_st a_st = {0};
    /* [logic] <a_st> */

    /* [logic] <a_st, a> */
}
```

---

> Authors 2026 Facooya and Fanone Facooya
