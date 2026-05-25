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

---

> Authors 2026 Facooya and Fanone Facooya
