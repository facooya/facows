# Convention
## Naming
**Variable**
- `entity_attribute`

**Function**
- `prefix_noun_verb`

**Parameters**
- destination, source, number
- destination, destination_number, source, source_number

## Rules
- No header pollution.
- Explicit type.
- - `int a = 10;` -> `I32 a = 10;`
- - `unsinged int a = 10;` -> `U32 a = 10;`
- Memory free or file descriptor close using `goto out;` in function bottom. After memory freed `mem = NULL;`, and after file diescriptor closed `fd = -1`.
- Should signed and 32 bit in like `if()`, `for()`, `while()` functions. 32 bit zero-extension. If using unsined `if (((U32) 1) < ((I32) -1))` is true, I32 foced typecasting to U32.
- Should `I32 func_ret = func(); if (func_ret < 0)`, should not `if (func() < 0)`.
- Should `const` keyword for readonly pointer. Like `const C8 * const ptr;`. Should not `const` keyword in struct definition. Should not `const` keyword to not pointer type, using `#define`.

---

> Authors 2026 Facooya and Fanone Facooya
