/*
 * packet-iextp.c - Wireshark dissector for IEX Transport Protocol
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

#include "packet-iextp.h"

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

/* Header Fields */
typedef enum _iextp_hf_type
{
  IEXTP_HF_VERSION,
  IEXTP_HF_PROTOCOL,
  IEXTP_HF_CHANNELID,
  IEXTP_HF_SESSIONID,
  IEXTP_HF_LENGTH,
  IEXTP_HF_MSGCOUNT,
  IEXTP_HF_OFFSET,
  IEXTP_HF_SEQNO,
  IEXTP_HF_SENDTIME,

  IEXTP_HF_MSGLEN,

  IEXTP_HF_LAST
} iextp_hf_type;

/* Marked Errors */
typedef enum _iextp_ef_type
{
  IEXTP_EF_BYTE_GAP,
  IEXTP_EF_MSG_GAP,

  IEXTP_EF_HEARTBEAT,

  IEXTP_EF_LAST
} iextp_ef_type;

/* A structure used to detect gaps */
typedef struct _iextp_convo_data
{
  /* The last packet's offset */
  gint64 last_pkt_offset;
  /* The last packet's length */
  gint64 last_pkt_len;
  /* The last packet's first seqnum */
  gint64 last_pkt_seqno_1;
  /* The last packet's last seqnum */
  gint64 last_pkt_seqno_n;
} iex_convo_data;

/* A structure containing details of a given packet */
typedef struct _iextp_packet_data
{
  guint64 gap_size;
  gint64  start_offset;
  gint64  start_seqno;
  gint64  last_seqno;
  gint32  total_len;
  guint32 __padding;
} iextp_packet_data;

/* IEX TP Segment Structure */
typedef struct _iextp_seg
{
  guint8  version;
  guint8  __reserved;
  guint16 protocol;
  guint32 channel;
  guint32 session;
  guint16 length;
  guint16 count;
  gint64  offset;
  gint64  first_seqno;
  gint64  send_time;
  guchar  msg_data[0];
} __attribute__( ( packed ) ) iextp_seg;


/* Classwide Vars */
static int proto_iextp = -1;
static int ett_iextp = -1;

static dissector_table_t iextp_protocol_dissector_table = NULL;
static dissector_handle_t iextp_handle = NULL;

static int hf_iextp_filter[IEXTP_HF_LAST] = { 0 };

static expert_field ei_iextp_errors[IEXTP_EF_LAST] =
{
  EI_INIT,
  EI_INIT
};


static void
dissect_iextp( tvbuff_t    *tvb,
               packet_info *pinfo,
               proto_tree  *ptree )
{
  guint16 protocol;
  guint16 msg_count;
  guint16 msg_len;
  guint32 session;
  guint32 channel;
  gint64 seqno;
  gint64 offset;
  dissector_handle_t subproto_handle;

  col_clear( pinfo->cinfo, COL_INFO );

  protocol = tvb_get_h_guint16( tvb, offsetof( iextp_seg, protocol ) );
  msg_count = tvb_get_h_guint16( tvb, offsetof( iextp_seg, count ) );
  session = tvb_get_h_guint32( tvb, offsetof( iextp_seg, session ) );
  channel = tvb_get_h_guint32( tvb, offsetof( iextp_seg, channel ) );
  seqno = tvb_get_letoh64( tvb, offsetof( iextp_seg, first_seqno ) );
  offset = tvb_get_letoh64( tvb, offsetof( iextp_seg, offset ) );
  msg_len = tvb_get_h_guint16( tvb, offsetof( iextp_seg, length ) );

  subproto_handle = dissector_get_uint_handle( iextp_protocol_dissector_table, protocol );
  if ( NULL != subproto_handle )
    {
      col_set_str( pinfo->cinfo, COL_PROTOCOL, dissector_handle_get_short_name( subproto_handle ) );

      if ( msg_len == 0 )
        {
          col_add_fstr( pinfo->cinfo, COL_INFO,
                        "Protocol: %s (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT
                        ", Heartbeat, Next byte: %" G_GINT64_FORMAT ", Next message: %" G_GINT64_FORMAT,
                        dissector_handle_get_short_name( subproto_handle ), protocol, channel, session, offset, seqno );
        }
      else if ( msg_count == 1 )
        {
          col_add_fstr( pinfo->cinfo, COL_INFO,
                        "Protocol: %s (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT ", Bytes: %"
                        G_GINT64_FORMAT " - %" G_GINT64_FORMAT ", Message: %" G_GINT64_FORMAT,
                        dissector_handle_get_short_name( subproto_handle ), protocol, channel, session, offset, offset + msg_len - 1,
                        seqno );
        }
      else
        {
          col_add_fstr( pinfo->cinfo, COL_INFO,
                        "Protocol: %s (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT ", Bytes: %"
                        G_GINT64_FORMAT " - %" G_GINT64_FORMAT ", Messages: %" G_GINT64_FORMAT " - %" G_GINT64_FORMAT,
                        dissector_handle_get_short_name( subproto_handle ), protocol, channel, session, offset, offset + msg_len - 1,
                        seqno, seqno + msg_count - 1 );
        }
    }
  else if ( msg_len == 0 )
    {
      col_add_fstr( pinfo->cinfo, COL_INFO,
                    "Protocol: Unknown (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT
                    ", Heartbeat, Next byte: %" G_GINT64_FORMAT ", Next message: %" G_GINT64_FORMAT,
                    protocol, channel, session, offset, seqno );
    }
  else if ( msg_count == 1 )
    {
      col_add_fstr( pinfo->cinfo, COL_INFO,
                    "Protocol: Unknown (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT
                    ", Bytes: %" G_GINT64_FORMAT " - %" G_GINT64_FORMAT ", Message: %" G_GINT64_FORMAT,
                    protocol, channel, session, offset, offset + msg_len - 1, seqno );
    }
  else
    {
      col_add_fstr( pinfo->cinfo, COL_INFO,
                    "Protocol: Unknown (%" G_GUINT16_FORMAT "): Channel: %" G_GUINT32_FORMAT ", Session: %" G_GUINT32_FORMAT
                    ", Bytes: %" G_GINT64_FORMAT " - %" G_GINT64_FORMAT ", Messages: %" G_GINT64_FORMAT " - %" G_GINT64_FORMAT,
                    protocol, channel, session, offset, offset + msg_len - 1, seqno, seqno + msg_count - 1 );
    }

  if ( NULL != ptree )
    {
      proto_item *ti;
      proto_tree *iextp_tree;
      nstime_t tv;
      guint16 total_len;

      ti = proto_tree_add_item( ptree, proto_iextp, tvb, 0, -1, ENC_NA );
      iextp_tree = proto_item_add_subtree( ti, ett_iextp );

      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_VERSION], tvb, offsetof( iextp_seg, version ),
                           sizeof( guint8 ), ENC_NA );

      proto_tree_add_protocol_format( iextp_tree, hf_iextp_filter[IEXTP_HF_PROTOCOL], tvb,
                                      offsetof( iextp_seg, protocol ), sizeof( guint16 ), "Message Protocol: %s",
                                      dissector_handle_get_short_name( subproto_handle ) );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_CHANNELID], tvb, offsetof( iextp_seg, channel ),
                           sizeof( guint32 ), ENC_LITTLE_ENDIAN );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_SESSIONID], tvb, offsetof( iextp_seg, session ),
                           sizeof( guint32 ), ENC_LITTLE_ENDIAN );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_LENGTH], tvb, offsetof( iextp_seg, length ),
                           sizeof( guint16 ), ENC_LITTLE_ENDIAN );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_MSGCOUNT], tvb, offsetof( iextp_seg, count ),
                           sizeof( guint16 ), ENC_LITTLE_ENDIAN );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_OFFSET], tvb, offsetof( iextp_seg, offset ),
                           sizeof( gint64 ), ENC_LITTLE_ENDIAN );
      proto_tree_add_item( iextp_tree, hf_iextp_filter[IEXTP_HF_SEQNO], tvb, offsetof( iextp_seg, first_seqno ),
                           sizeof( gint64 ), ENC_LITTLE_ENDIAN );

      tv.secs = ( gint64 ) tvb_get_letoh64( tvb, offsetof( iextp_seg, send_time ) ) / 1000000000L;
      tv.nsecs = ( gint )( tvb_get_letoh64( tvb, offsetof( iextp_seg, send_time ) ) - ( tv.secs * 1000000000L ) );
      proto_tree_add_time( iextp_tree, hf_iextp_filter[IEXTP_HF_SENDTIME], tvb, offsetof( iextp_seg, send_time ),
                           sizeof( gint64 ), &tv );

      total_len = 0;

      for ( guint16 msg_i = 0; msg_i < msg_count; msg_i++ )
        {
          proto_tree *msg_ptree;
          guint16 msg_len;
          tvbuff_t *next_tvb;
          proto_item *pi;

          msg_len = tvb_get_h_guint16( tvb, sizeof( iextp_seg ) );

          pi = proto_tree_add_text( iextp_tree, tvb, sizeof( iextp_seg ) + total_len + sizeof( guint16 ),
                                    sizeof( guint16 ) + msg_len, "Message" );

          next_tvb = tvb_new_subset_length( tvb, sizeof( iextp_seg ) + total_len + sizeof( guint16 ), msg_len );

          msg_ptree = proto_item_add_subtree( pi, msg_i );

          proto_tree_add_item( msg_ptree, hf_iextp_filter[IEXTP_HF_MSGLEN], tvb, sizeof( iextp_seg ) + total_len,
                               sizeof( guint16 ), ENC_LITTLE_ENDIAN );

          call_dissector( subproto_handle, next_tvb, pinfo, msg_ptree );

          total_len += sizeof( guint16 ) + msg_len;
        }
    }
}


static gboolean
dissect_iextp_heur( tvbuff_t    *tvb,
                    packet_info *pinfo,
                    proto_tree  *ptree,
                    void        *data __attribute__( ( unused ) ) )
{
  if ( sizeof( iextp_seg ) > tvb_captured_length( tvb ) )
    {
      return FALSE;
    }

  if ( 1 != tvb_get_bits8( tvb, offsetof( iextp_seg, version ), 8 ) )
    {
      return FALSE;
    }

  if ( 0 == tvb_get_letohs( tvb, offsetof( iextp_seg, protocol ) ) )
    {
      return FALSE;
    }

  if ( 0 > ( gint64 ) tvb_get_letoh64( tvb, offsetof( iextp_seg, offset ) ) )
    {
      return FALSE;
    }

  if ( 0 > ( gint64 ) tvb_get_letoh64( tvb, offsetof( iextp_seg, first_seqno ) ) )
    {
      return FALSE;
    }

  if ( 0 > ( gint64 ) tvb_get_letoh64( tvb, offsetof( iextp_seg, send_time ) ) )
    {
      return FALSE;
    }

  if ( 0 == tvb_get_h_guint32( tvb, offsetof( iextp_seg, channel ) ) )
    {
      return FALSE;
    }

  if ( 0 == tvb_get_h_guint32( tvb, offsetof( iextp_seg, session ) ) )
    {
      return FALSE;
    }

  dissect_iextp( tvb, pinfo, ptree );

  return TRUE;
}


void
proto_reg_handoff_iextp( void )
{
  if ( NULL == iextp_handle )
    {
      iextp_handle = create_dissector_handle( dissect_iextp, proto_iextp );
      dissector_add_handle( "udp.port", iextp_handle );
      heur_dissector_add( "udp", dissect_iextp_heur, proto_iextp );
    }
}


void
proto_register_iextp( void )
{
  static hf_register_info hf[] =
  {
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_VERSION],
      .hfinfo = {
        .name    = "Version",
        .abbrev  = "iextp.version",
        .type    = FT_UINT8,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The version of IEX-TP in this packet.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_PROTOCOL],
      .hfinfo = {
        .name    = "Protocol",
        .abbrev  = "iextp.proto",
        .type    = FT_PROTOCOL,
        .display = BASE_NONE,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The ID of the protocol which describes messages in this segment.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_CHANNELID],
      .hfinfo = {
        .name    = "Channel ID",
        .abbrev  = "iextp.chanid",
        .type    = FT_UINT32,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The channel all messages in this segment belong to.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_SESSIONID],
      .hfinfo = {
        .name    = "Session ID",
        .abbrev  = "iextp.sessid",
        .type    = FT_UINT32,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The session all messages in this segment belong to.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_LENGTH],
      .hfinfo = {
        .name    = "Length",
        .abbrev  = "iextp.length",
        .type    = FT_UINT16,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The length of the data (including message lengths) in this segment.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_MSGCOUNT],
      .hfinfo = {
        .name    = "Count",
        .abbrev  = "iextp.count",
        .type    = FT_UINT16,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The number of messages in this segment.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_OFFSET],
      .hfinfo = {
        .name    = "Offset",
        .abbrev  = "iextp.offset",
        .type    = FT_INT64,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The offset of this segment's data within the stream.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_SEQNO],
      .hfinfo = {
        .name    = "First Message Sequence Number",
        .abbrev  = "iextp.seq",
        .type    = FT_INT64,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The sequence number of the first message in this segment.",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_SENDTIME],
      .hfinfo = {
        .name    = "Send Time",
        .abbrev  = "iextp.time",
        .type    = FT_ABSOLUTE_TIME,
        .display = ABSOLUTE_TIME_UTC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The time the segment was sent (in nanoseconds since epoch).",
        HFILL
      }
    },
    {
      .p_id   = &hf_iextp_filter[IEXTP_HF_MSGLEN],
      .hfinfo = {
        .name    = "Message Length",
        .abbrev  = "iextp.msglen",
        .type    = FT_UINT16,
        .display = BASE_DEC,
        .strings = NULL,
        .bitmask = 0x0,
        .blurb   = "The length of the message in question.",
        HFILL
      }
    }
  };

  static int *ett[] =
  {
    &ett_iextp
  };

  static ei_register_info ei[] =
  {
    {
      .ids    = &ei_iextp_errors[IEXTP_EF_BYTE_GAP],
      .eiinfo = {
        .name     = "iextp.gap_bytes",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous bytes not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextp_errors[IEXTP_EF_MSG_GAP],
      .eiinfo = {
        .name     = "iextp.gap_msg",
        .group    = PI_SEQUENCE,
        .severity = PI_ERROR,
        .summary  = "Previous messages not captured (common at capture start)",
        EXPFILL
      }
    },
    {
      .ids    = &ei_iextp_errors[IEXTP_EF_HEARTBEAT],
      .eiinfo = {
        .name     = "iextp.heartbeat",
        .group    = PI_RESPONSE_CODE,
        .severity = PI_CHAT,
        .summary  = "The segment is a heartbeat",
        EXPFILL
      }
    }
  };

  if ( -1 == proto_iextp )
    {
      expert_module_t *expert_iextp;

      proto_iextp = proto_register_protocol( "IEX Transport Protocol", "IEX-TP", "iextp" );

      proto_register_field_array( proto_iextp, hf, array_length( hf ) );
      proto_register_subtree_array( ett, array_length( ett ) );

      expert_iextp = expert_register_protocol( proto_iextp );
      expert_register_field_array( expert_iextp, ei, array_length( ei ) );

      iextp_protocol_dissector_table = register_dissector_table( "iextp.proto", "IEX-TP Protocol",
                                                                 FT_UINT16, BASE_DEC );
    }
}
