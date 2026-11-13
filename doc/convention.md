# Convention
## Naming
**Variable**
- `entity`
- `attribute`
- `entity_attribute`
- bool type: `verb_*`

Bool type verb for examples:
- is
- use
- need

Attribute examples:
- array `*_arr`
- buffer `*_buf`
- format `*_fmt`
- opaque `*_opq`
- string `*_str`
- pointer `*_p`
- double pointer `*_pp`
- pointer for scan `p_*`
- minimum and maximum: `*_min`, `*_max`
- number of size: `*_n`
- length of string, except null: `*_len`
- count: `*_cnt`
- accumulation: `*_acc`

**Function**
- `prefix_noun_verb`
- local: `_*`
Verb for examples:
- init
- parse
- read/write
- exit
- run

## Rules
**Must**
- Must not use overflow functions like `strlen()`.
- Must use explicit type.
- - `int a = 10;` -> `s32 a = 10;`
- - `unsinged int a = 10;` -> `u32 a = 10;`
- Must memory freed `mem = nullptr;`, and after file diescriptor closed `fd = -1`. E.g., `free(mem); mem = nullptr; if (fd >= 0) { close(fd); fd = -1; }`

**Should**
- Should not header pollution.
- Should `s32 func_ret = func(); if (func_ret < 0)`, should not `if (func() < 0)`.
- Readonly data should use `static constexpr` instead of `#define`.
- Should use memory free or file descriptor close using `goto out;` and `out` label in function bottom.
- Should use `void` parameter, if no parameters (e.g., `s32 func(void); ret = func();`).

**May**
- Order for parameters e.g., `func(dst, src, num)`, `func(dst, dst_n, src, src_n)`.

---

### Variables
Order of variables for example:
```c
/* require free */
char *ptr = nullptr;

/* file desciptor */
s32 fd = -1;

/* global variable in this function */
s32 ret = 0;

/* normal variable */
static const char abc_str[] = "abc";
s32 a = 0;
/* logic using 'abc_str' and 'a' */

struct a_st a_st = {0};
/* logic using 'a_st' */
```

---

### Header
```c
/* No header pollution */
#include "factype.h"
#include "facerr.h"

/* ISO C */
#include <stdio.h>
#include <stdlib.h>

/* POSIX */
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* External */
```

---

### Newline
Newline for 80-110. If newline for function to tab x2, and grouping.  
Examples:
```c
s32 function(char *destination_buffer, s32 destination_number, const char *source_buffer, s32 source_number);

s32 main(void) {
    /* Line change for function parameter type, indented 2 */
    s32 ret = function(char *destination_buffer, s32 destination_number,
            const char *source_buffer, s32 source_number);

    /* Line change for string type, indented 1 */
    printf("Line change Line change Line change Line change Line change Line change Line change"
        "Line change Line Change %s, %d\n", __FILE__, __LINE__);
    return 0;
}

s32 function(char *destination_buffer, s32 destination_number,
        const char *source_buffer, s32 source_number) {
    printf("");
    return 0;
}
```

---

### Resource Free
Examples:
```c
s32 func(void) {
    char *buf = nullptr;
    s32 fd = -1;
    s32 ret = -1;

    constexpr s32 buf_max = 1024;
    buf = calloc(buf_max, 1);
    if (buf == nullptr) {
        FAC_ERR(FAC_ERR_NULL);
        ret = -1;
        goto out;
    }

    constexpr s32 file_str[] = "./file.txt";
    fd = open(file_str, O_RDONLY);
    if (fd < 0) {
        FAC_ERR(FAC_ERR_FD);
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    free(buf);
    buf = nullptr;

    if (fd >= 0) {
        close(fd);
        fd = -1;
    }

    return ret;
}
```

---

> Maintained by Facooya and Fanone Facooya, 2026
