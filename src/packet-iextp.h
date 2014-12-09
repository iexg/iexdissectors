/*
 * packet-iextp.h - Wireshark dissector for IEX Transport Protocol
 *
 * Copyright (C) 2014 IEX Group, Inc.
 *
 * Authors:
 *
 * james.cape@iextrading.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __PACKET_IEXTP_H__
#define __PACKET_IEXTP_H__

#pragma GCC diagnostic ignored "-Wpadded"
#include <glib.h>
#pragma GCC diagnostic error "-Wpadded"

G_BEGIN_DECLS

void proto_reg_handoff_iextp( void );
void proto_register_iextp( void );

G_END_DECLS

#endif /* __PACKET_IEXTP_H__ */
