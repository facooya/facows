/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_H
#define FWS_H

#include "factype.h"

void fws_child_run(struct fws_child_ctx *child_ctx);
s32 fws_parent_run(struct fws_parent_ctx *parent_ctx);

#endif
