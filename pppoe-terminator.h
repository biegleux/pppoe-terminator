/*
 * pppoe-terminator v0.2 - terminate PPPoE sessions
 *
 * Copyright (c) 2008-2010, Tibor Bombiak
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * chap-challenger is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */

#include <net/ethernet.h>

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY	0x8863

/* PPPoE codes */
#define CODE_PADT		0xA7

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD		6 /* type, code, session, length */
#define PPPOE_HEADERLEN		(sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD	(ETH_DATA_LEN - PPPOE_OVERHEAD)

/* A PPPoE Packet, including Ethernet headers */
typedef struct PPPoEPacketStruct {
    struct ethhdr ethHdr;	/* Ethernet header */
    unsigned int type:4;	/* PPPoE Type (must be 1) */
    unsigned int ver:4;		/* PPPoE Version (must be 1) */
    unsigned int code:8;	/* PPPoE code */
    unsigned int session:16;	/* PPPoE session */
    unsigned int length:16;	/* Payload length */
    unsigned char payload[MAX_PPPOE_PAYLOAD];
} PPPoEPacket;

#define I_FLG	0
#define A_FLG	1
#define D_FLG	2
#define S_FLG	3

#define SETFLAG(x, flg)	((x) |= 0x01 << (flg))
#define GETFLAG(x, flg)	(((x) >> (flg)) & 0x01)

#define DEF_PKTS	10
#define MAX_PKTS	200
#define VERSION		"0.2"
