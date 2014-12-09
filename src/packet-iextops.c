/*
 * packet-iextp.c - Wireshark dissector for IEX TOPS Message Protocol
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */

#include "packet-iextops.h"

#pragma GCC diagnostic ignored "-Wpadded"

#include <glib.h>
#include <gmodule.h>

#include <register.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#pragma GCC diagnostic error "-Wpadded"

#include <libintl.h>
#include <stdbool.h>

#define IEXTP_PROTO_IEXTOPS 32769
#define IEXTOPS_SYMBOL_LEN 8
#define IEXTOPS_FLAGS_BITLEN 8

typedef enum _iextops_flags
{
  IEXTOPS_FLAGS_PREPOSTMKT = 1 << 7,
  IEXTOPS_FLAGS_HALTED     = 1 << 8,

  IEXTOPS_FLAGS_ALL        = 0xc0
} iextops_flags;

/* Fields */
typedef enum _iextops_hf_type
{
  IEXTOPS_HF_MSGTYPE,
  IEXTOPS_HF_FLAGS,

  IEXTOPS_HF_FLAGS_HALTED,
  IEXTOPS_HF_FLAGS_PREPOSTMKT,

  IEXTOPS_HF_TIMESTAMP,
  IEXTOPS_HF_SYMBOL,
  IEXTOPS_HF_BIDSIZE,
  IEXTOPS_HF_BIDPRICE,
  IEXTOPS_HF_ASKPRICE,
  IEXTOPS_HF_ASKSIZE,

  IEXTOPS_HF_LAST
} iextops_hf_type;

/* Errors */
typedef enum _iextops_ef_type
{
  IEXTOPS_EF_UNKNOWN_TYPE,
  IEXTOPS_EF_INVALID_FLAGS,
  IEXTOPS_EF_INVALID_TIME,
  IEXTOPS_EF_INVALID_BID,
  IEXTOPS_EF_INVALID_ASK,

  IEXTOPS_EF_LAST
} iextops_ef_type;

typedef enum _iextops_msg_type
{
  IEXTOPS_MSG_QUOTE = 0x51,
  IEXTOPS_MSG_LAST
} iextops_msg_type;

/* IEX TOPS Message Structure */
typedef struct _iextops_msg
{
  guint8  msgtype;
  guint8  flags;
  gint64  timestamp;
  gchar   symbol[8];
  guint32 bid_size;
  gint64  bid_price;
  gint64  ask_price;
  guint32 ask_size;
} __attribute__( ( packed ) ) iextops_msg;

/* Classwide Vars */
static int proto_iextops = -1;
static int ett_iextops = -1;

static dissector_handle_t iextops_handle = NULL;

static int hf_iextops_filter[IEXTOPS_HF_LAST] = { 0 };

static expert_field ei_iextops_errors[IEXTOPS_EF_LAST] =
{
  EI_INIT,
  EI_INIT
};

static const value_string iextops_msgtype_values[IEXTOPS_MSG_LAST] =
{
  { IEXTOPS_MSG_QUOTE, "Quote" },
};

static void
dissect_iextops( tvbuff_t    *tvb __attribute__( ( unused ) ),
                 packet_info *pinfo __attribute__( ( unused ) ),
                 proto_tree  *ptree )
{
  proto_item *ti;
  nstime_t tv;
  guint64 price;

  ti = proto_tree_get_parent( ptree );

  proto_item_set_text( ti, "%s Message",
                       val_to_str_const( tvb_get_bits8( tvb, 0, 8 ), iextops_msgtype_values, "Unknown" ) );

  proto_tree_add_item( ptree, hf_iextops_filter[IEXTOPS_HF_MSGTYPE], tvb, offsetof( iextops_msg, msgtype ),
                       sizeof( guint8 ), ENC_NA );

  proto_tree_add_item( ptree, hf_iextops_filter[IEXTOPS_HF_FLAGS], tvb, offsetof( iextops_msg, flags ),
                       sizeof( guint8 ), ENC_NA );

  proto_tree_add_bits_item(ptree, hf_iextops_filter[IEXTOPS_HF_FLAGS_HALTED], tvb, offsetof(iextops_msg, flags) * 8 + 0, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_bits_item(ptree, hf_iextops_filter[IEXTOPS_HF_FLAGS_PREPOSTMKT], tvb, offsetof(iextops_msg, flags) * 8 + 1, 1, ENC_LITTLE_ENDIAN);
  // proto_tree_add_boolean( ptree, hf_iextops_filter[IEXTOPS_HF_FLAGS_HALTED], tvb,
  //                         offsetof( iextops_msg, flags ), 1, tvb_get_bits8( tvb, offsetof( iextops_msg, flags ), 8 ) );
  // proto_tree_add_boolean( ptree, hf_iextops_filter[IEXTOPS_HF_FLAGS_PREPOSTMKT], tvb,
  //                         offsetof( iextops_msg, flags ), 1, tvb_get_bits8( tvb, offsetof( iextops_msg, flags ), 8 ) );

  tv.secs = ( gint64 ) tvb_get_letoh64( tvb, offsetof( iextops_msg, timestamp ) ) / 1000000000L;
  tv.nsecs = ( gint )( tvb_get_letoh64( tvb, offsetof( iextops_msg, timestamp ) ) - ( tv.secs * 1000000000L ) );
  proto_tree_add_time( ptree, hf_iextops_filter[IEXTOPS_HF_TIMESTAMP], tvb, offsetof( iextops_msg, timestamp ),
                       sizeof( gint64 ), &tv );

  proto_tree_add_text( ptree, tvb, offsetof( iextops_msg, symbol ), IEXTOPS_SYMBOL_LEN, "Symbol: %8s",
                       tvb_get_string_enc( wmem_file_scope(), tvb, offsetof( iextops_msg, symbol ),
                                           IEXTOPS_SYMBOL_LEN, ENC_ASCII ) );

  proto_tree_add_item( ptree, hf_iextops_filter[IEXTOPS_HF_BIDSIZE], tvb, offsetof( iextops_msg, bid_size ),
                       sizeof( guint32 ), ENC_LITTLE_ENDIAN );
  price = tvb_get_letoh64( tvb, offsetof( iextops_msg, bid_price ) );
  proto_tree_add_text( ptree, tvb, offsetof( iextops_msg, bid_price ), sizeof( gint64 ), "Bid Price: %ld.%05ld",
                       ( price / 10000 ), ( price - ( ( price / 10000 ) * 10000 ) ) );

  price = tvb_get_letoh64( tvb, offsetof( iextops_msg, ask_price ) );
  proto_tree_add_text( ptree, tvb, offsetof( iextops_msg, ask_price ), sizeof( gint64 ),
                       "Ask Price: %ld.%05ld", ( price / 10000 ), ( price - ( ( price / 10000 ) * 10000 ) ) );
  proto_tree_add_item( ptree, hf_iextops_filter[IEXTOPS_HF_ASKSIZE], tvb, offsetof( iextops_msg, ask_size ),
                       sizeof( guint32 ), ENC_LITTLE_ENDIAN );
}

void
proto_reg_handoff_iextops( void )
{
  if ( NULL == iextops_handle )
    {
      iextops_handle = create_dissector_handle( dissect_iextops, proto_iextops );
      dissector_add_uint( "iextp.proto", IEXTP_PROTO_IEXTOPS, iextops_handle );
    }
}


void
proto_register_iextops( void )
{
  static hf_register_info hf[] =
  {
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_MSGTYPE],
      .hfinfo = {
        .name    = "Message Type",
        .abbrev  = "iextops.type",
        .type    = FT_UINT8,
        .display = BASE_DEC,
        .strings = VALS( iextops_msgtype_values ),
        .bitmask = 0x0,
        .blurb   = "The type of message.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_FLAGS],
      .hfinfo = {
        .name    = "Flags",
        .abbrev  = "iextops.flags",
        .type    = FT_UINT8,
        .display = BASE_HEX,
        .strings = NULL,
        .bitmask = 0xFF,
        .blurb   = "The flags for a given message",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_FLAGS_HALTED],
      .hfinfo = {
        .name    = "Halted",
        .abbrev  = "iextops.flags.halted",
        .type    = FT_BOOLEAN,
        .display = IEXTOPS_FLAGS_BITLEN,
        .strings = TFS( &tfs_yes_no ),
        .bitmask = 0x0,
        .blurb   = "The symbol is halted",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_FLAGS_PREPOSTMKT],
      .hfinfo = {
        .name    = "Pre/Post-Market",
        .abbrev  = "iextops.flags.prepost",
        .type    = FT_BOOLEAN,
        .display = IEXTOPS_FLAGS_BITLEN,
        .strings = TFS( &tfs_yes_no ),
        .bitmask = 0x0,
        .blurb   = "This quote is valid outside of market hours",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_TIMESTAMP],
      .hfinfo = {
        .name    = "Time",
        .abbrev  = "iextops.time",
        .type    = FT_ABSOLUTE_TIME,
        .display = ABSOLUTE_TIME_UTC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The time the quote was updated (in nanoseconds since epoch).",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_SYMBOL],
      .hfinfo = {
        .name    = "Symbol",
        .abbrev  = "iextops.sym",
        .type    = FT_STRING,
        .display = BASE_NONE,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The symbol this quote is for.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_BIDSIZE],
      .hfinfo = {
        .name    = "Bid Size",
        .abbrev  = "iextops.bidsize",
        .type    = FT_UINT32,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The cumulative displayed size resting on at the best bid for the given symbol.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_BIDPRICE],
      .hfinfo = {
        .name    = "Bid Price",
        .abbrev  = "iextops.bid",
        .type    = FT_INT64,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The best bid for the given symbol.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_ASKPRICE],
      .hfinfo = {
        .name    = "Ask Price",
        .abbrev  = "iextops.ask",
        .type    = FT_INT64,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The best displayed offer for the given symbol.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextops_filter[IEXTOPS_HF_ASKSIZE],
      .hfinfo = {
        .name    = "Ask Size",
        .abbrev  = "iextops.asksize",
        .type    = FT_UINT32,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The cumulative displayed size resting at the best offer for the given symbol.",
        HFILL
      }
    },
  };

  static int *ett[] =
  {
    &ett_iextops
  };

  static ei_register_info ei[] =
  {
    {
      .ids    = &ei_iextops_errors[IEXTOPS_EF_UNKNOWN_TYPE],
      .eiinfo = {
        .name     = "iextops.unknown_type",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous bytes not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextops_errors[IEXTOPS_EF_INVALID_FLAGS],
      .eiinfo = {
        .name     = "iextops.invalid_flags",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous bytes not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextops_errors[IEXTOPS_EF_INVALID_TIME],
      .eiinfo = {
        .name     = "iextops.invalid_time",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous bytes not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextops_errors[IEXTOPS_EF_INVALID_BID],
      .eiinfo = {
        .name     = "iextops.invalid_bid",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous bytes not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextops_errors[IEXTOPS_EF_INVALID_ASK],
      .eiinfo = {
        .name     = "iextops.invalid_ask",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous messages not captured (common at capture start)",
        EXPFILL
      }
    }
  };

  if ( -1 == proto_iextops )
    {
      expert_module_t *expert_iextops;

      proto_iextops = proto_register_protocol( "IEX TOPS", "IEX-TOPS", "iextops" );

      proto_register_field_array( proto_iextops, hf, array_length( hf ) );
      proto_register_subtree_array( ett, array_length( ett ) );

      expert_iextops = expert_register_protocol( proto_iextops );
      expert_register_field_array( expert_iextops, ei, array_length( ei ) );
    }
}
