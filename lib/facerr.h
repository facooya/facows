/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_ERR_H
#define FAC_ERR_H

#define FAC_ERR(msg) fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, (msg))

#define FAC_ERR_LIMIT "limit exceeded"
#define FAC_ERR_NULL "null pointer"
#define FAC_ERR_FORMAT "invalid format"

#endif
