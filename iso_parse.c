// Date:   Fri Feb 14 04:42:28 PM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include "iso_parse.h"

static void trans_state(State* state, const u8 byte) {
  assert(state->state_count < 4);
  state->state |= (u32)byte << (state->state_count * 8);
  state->state_count++;
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
