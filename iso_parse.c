// Date:   Fri Feb 14 04:42:28 PM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include "iso_parse.h"

static u32 ber_decode_length(u8* buf, int* len, u32 pos, u32 max_pos) {
  // assert the simplest length form
  assert(!(buf[pos] & 0x80));
  *len = buf[pos++];
  return pos;
}

CotpIndication parse_cotp(IsoConnection* self, ByteBuffer* msg) {
  u8* buf = msg->buf;
  const u8 len = buf[0];
  self->cotp_pdu_type = buf[1];
  switch (buf[1]) {
    // conncect confirm
    case 0xd0:
      return COTP_CONNECT_CONFIRM;
      break;

      // data
    case 0xf0:
      self->cotp_payload.buf = buf + 3;
      self->cotp_payload.size = msg->size - 3;
      if (buf[2] & 0x80) {
        return COTP_DATA;
      } else {
        return COTP_MORE_FRAGMENTS_FOLLOW;
      }

    default:
      return COTP_ERROR;
  }
}

SessionIndication parse_session(IsoConnection* self, ByteBuffer* msg) {
  u8* buf = msg->buf;
  const u8 id = buf[0], len = buf[1];
  self->session_spdu_type = id;

  if (len <= 1) return SESSION_ERROR;

  switch (id) {
    case 14: /* ACCEPT SPDU */
      if (len != (msg->size - 2)) return SESSION_ERROR;
      if (parse_session_header_parameters(self, msg, len) == SESSION_OK)
        return SESSION_CONNECT;
      else return SESSION_ERROR;

    case 1: /* Give token / data SPDU */
      if (msg->size < 4) 
        return SESSION_ERROR;
      if (len == 0 && (buf[2] == 1) && (buf[3] == 0)) {
        self->user_data.buf = buf + 4;
        self->user_data.size = msg->size - 4;
        return SESSION_DATA;
      }
      else return SESSION_ERROR;

    default:
      return SESSION_ERROR;
  }
}

SessionIndication parse_session_header_parameters(IsoConnection* self, ByteBuffer* msg, const u32 parameter_octets) {
  u32 pos = 2;
  u8* buf = msg->buf;

  while (pos < parameter_octets + 2) {
    const u8 tag = buf[pos++], len = buf[pos++];

    switch (tag) {
      case 1:
      case 5:
      case 17:
      case 20:
      case 25:
      case 49:
      case 51:
      case 52:
      case 60:
        pos += len;
        break;

      case 193:
        self->user_data.buf = buf + pos;
        self->user_data.size = msg->size - pos;
        return SESSION_OK;
    }
  }
  return SESSION_ERROR;
}

int parse_presentation_user_data(IsoConnection* self, ByteBuffer* msg) {
  u8* buf = msg->buf;
  const int max_buf_pos = msg->size;
  int pos = 0;

  if (max_buf_pos < 9) {
    assert(0);
    return 0;
  }

  if (buf[pos++] != 0x61) {
    assert(0);
    return 0;
  }

  int len;
  pos = ber_decode_length(buf, &len, pos, max_buf_pos);
  assert(len > 0);

  if (buf[pos++] != 0x30) {
    assert(0);
    return 0;
  }

  pos = ber_decode_length(buf, &len, pos, max_buf_pos);
  u8 has_abstract_syntax_name = 0;

  while (pos < max_buf_pos) {
    const u8 tag = buf[pos++];
    pos = ber_decode_length(buf, &len, pos, max_buf_pos);

    switch (tag) {
      case 0x02: /* abstract-syntax-name */
        has_abstract_syntax_name = 1;
        self->presentation_context_id = buf[pos];
        pos += len;
        break;

      case 0x06: /* transfer-syntax-name */
        if (buf[pos] != 0x51 || buf[pos + 1] != 0x01) {
          assert(0);
          return 0;
        }
        pos += len;
        break;

      case 0xa0: /* presentation-data */
        if (has_abstract_syntax_name == 0) {
          assert(0);
          return 0;
        }
        self->mms_data.buf = &buf[pos];
        self->mms_data.size = len;
        return 1;
    }
  }
  return 0;
}

int parse_mms(IsoConnection* self, ByteBuffer* msg) {
  u8* buf = msg->buf;
  const u32 max_pos = msg->size;
  u32 pos = 0;
  
  assert(buf[pos] == 0xa1 || buf[pos] == 0xa9);
  self->mms_pdu_type = buf[pos++];
  int len;
  pos = ber_decode_length(buf, &len, pos, max_pos);

  self->mms_service_type = buf[pos];
  return 1;
}

u32 merge_state(IsoConnection* self) {
  const u32 cotp_pdu_type = self->cotp_pdu_type;
  const u32 session_spdu_type = self->session_spdu_type;
  const u32 mms_pdu_type = self->mms_pdu_type;
  const u32 mms_service_type = self->mms_service_type;

  return cotp_pdu_type << 24 | session_spdu_type << 16 | mms_pdu_type << 8 | mms_service_type;
}
