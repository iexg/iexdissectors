/**
 * plugin.c - Wireshark dissector plugin from IEX
 *
 * Copyright (C) 2013-2014 IEX Group, Inc.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */

#include "packet-iexdissectors.h"

#include "packet-iextp.h"
#include "packet-iextops.h"

G_MODULE_EXPORT void
plugin_reg_handoff (void)
{
  proto_reg_handoff_iextp();
  proto_reg_handoff_iextops();
}

G_MODULE_EXPORT void
plugin_register (void)
{
  proto_register_iextp();
  proto_register_iextops();
}
