/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef NFT_H
#define NFT_H

void nft_init(short http_port, short https_port);
void nft_ban_dos(const struct sockaddr_in6 *client_addr, struct fws_nft *nft_list, size_t list_size);

#endif
