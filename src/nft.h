/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef NFT_H
#define NFT_H

void nft_init(uint16_t http_port, uint16_t https_port);
void nft_dos_ban(const struct sockaddr_in6 *client_addr, struct fws_nft *nft_list, size_t list_size);

#endif
