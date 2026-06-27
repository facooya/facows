# Convention
## Naming
**Variable**
- `entity`
- `attribute`
- `entity_attribute`
- bool type: `verb_*`
Bool type verb for example:
- is
- use
- need

**Function**
- `prefix_noun_verb`
- local: `_*`
Verb for example:
- init
- parse
- read/write
- exit
- run

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
- Must memory freed `mem = nullptr;`, and after file diescriptor closed `fd = -1`. E.g., `free(mem); mem = nullptr; if (fd > 0) { close(fd); fd = -1; }`

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
    char *ptr = nullptr;

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

## Example code
Show variables order and resources free:
```c
/* No header pollution */
#include "factype.h"

/* ISO C */
#include <stdio.h>
#include <stdlib.h>

/* POSIX */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static const char path[] = "./test.txt";

static s32 _fd_read(void);
static s32 _fp_write(void);

s32 main(void) {
	/* Constants definition */
	constexpr u64 enum_b_num = 100;
	constexpr u64 static_size = 1000;
	enum {ENUM_A, ENUM_B = enum_b_num};
	struct ghi {
		u64 size;
		s32 num;
	};

    /* Statics */
    static const char abc_str[] = "abc";
    static const char def_str[] = "def";
    static const char *const alpha_str_arr[] = {abc_str, def_str};
	static const struct ghi ghi_arr[] = {
		/* Designated initializer */
		[0] = {.size = 10, .num = ENUM_A},
		[1] = {.size = static_size, .num = ENUM_B}
	};

    /* Resources */
    char *alloc_buf = nullptr;

    /* Reusable */
    s32 ret = 0;

	/* Allocate and free */
    constexpr u64 alloc_buf_n = 128;
    alloc_buf = calloc(alloc_buf_n, 1);
    if (alloc_buf == nullptr) {
        fprintf(stderr, "main(): calloc(): failed\n");
        ret = -1;
        goto out;
    }

    constexpr u64 abc_str_len = sizeof(abc_str) - 1;
    constexpr u64 alpha_str_arr_cap = sizeof(alpha_str_arr) / sizeof(alpha_str_arr[0]);
    printf("abc_str_len: %lu, alpha_str_arr_cap: %lu\n", abc_str_len, alpha_str_arr_cap);

	/* The 'i' follow type to 'ghi_arr_cap' type. */
	constexpr u64 ghi_arr_cap = sizeof(ghi_arr) / sizeof(ghi_arr[0]);
	for (u64 i=0; i<ghi_arr_cap; i++) {
		printf("ghi_arr[%lu]: size: %lu, num: %d\n", i, ghi_arr[i].size, ghi_arr[i].num);
	}

	/* File read/write use 'file pointer' and 'file descriptor'. */
	ret = _fp_write();
	if (ret < 0) {
		fprintf(stderr, "main(): _fp_write(): failed: %d\n", ret);
		ret = -1;
		goto out;
	}

	ret = _fd_read();
	if (ret < 0) {
		fprintf(stderr, "main(): _fd_read(): failed: %d\n", ret);
		ret = -1;
		goto out;
	}

	/* Trust top variables for resource definition and 'out' label.
	 * Shuold not free (e.g., free(), close()) in logic section. */

    ret = 0;
out:
    free(alloc_buf);
    alloc_buf = nullptr;

	/* For 'main()' return. */
	if (ret < 0) {
		ret *= -1;
	}
    return ret;
}

static s32 _fd_read(void) {
	char *buf = nullptr; // resource
	s32 fd = -1; // resource
	s32 ret = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "_fd_read(): open(): failed: %d\n", fd);
		ret = -1;
		goto out;
	}

	struct stat stat = {0};
	ret = fstat(fd, &stat);
	if (ret < 0) {
		fprintf(stderr, "_fd_read(): fstat(): failed: %d\n", ret);
		ret = -1;
		goto out;
	}

	u32 n = stat.st_size;
	buf = calloc(n+1, 1); /* The '+1' for null char. */
	s64 read_ret = read(fd, buf, n);
	if (read_ret < 0) {
		fprintf(stderr, "_fd_read(): read(): failed: %ld\n", read_ret);
		ret = -1;
		goto out;
	}
	buf[n] = '\0'; /* Add null char for safety. */

	printf("%s", buf);

	ret = 0;
out:
	free(buf);
	buf = nullptr;

	if (fd < 0) {
		close(fd);
		fd = -1;
	}
	return ret;
}

static s32 _fp_write(void) {
	static const char file_str[] = "File line 1\nFile line 2\n";
	FILE *fp = nullptr; // resource
	s32 ret = 0;

	fp = fopen(path, "w");
	if (fp == nullptr) {
		fprintf(stderr, "_fp_write(): fopen(): failed\n");
		ret = -1;
		goto out;
	}

	ret = fputs(file_str, fp);
	if (ret < 0) {
		fprintf(stderr, "_fp_write(): fputs(): failed: %d\n", ret);
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	if (fp != nullptr) {
		fclose(fp);
		fp = nullptr;
	}
	return ret;
}
```

---

> Maintained by Facooya and Fanone Facooya, 2026
