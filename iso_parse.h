// Date:   Fri Feb 14 04:33:04 PM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian


#ifndef _ISO_PARSE_TYPES_H
#define _ISO_PARSE_TYPES_H

#include "types.h"
#include "assert.h"

typedef struct {
  u8* buf;
  i32 size;
} ByteBuffer;

typedef struct {
  u32 state;
  u32 state_count;
} State;

// typedef enum: u8 {
//   GetNameList = 0xa1,
// } ConfirmedServiceResponse;

typedef struct {
  u8 cotp_pdu_type;
  u8 session_spdu_type;
  u8 presentation_context_id;

  u8 mms_pdu_type;
  u8 mms_service_type;

  ByteBuffer cotp_payload;
  ByteBuffer user_data;
  ByteBuffer mms_data;
} IsoConnection;

typedef enum {
  COTP_ERROR,
  COTP_CONNECT_CONFIRM,
  COTP_DATA,
  COTP_MORE_FRAGMENTS_FOLLOW,
} CotpIndication;

typedef enum {
  SESSION_OK,
  SESSION_ERROR,
  SESSION_CONNECT,
  SESSION_GIVE_TOKEN,
  SESSION_DATA,
  SESSION_ABORT,
  SESSION_FINISH,
  SESSION_DISCONNECT,
  SESSION_NOT_FINISHED
} SessionIndication;

typedef enum {
  ACSE_ERROR,
} AcseIndication;

CotpIndication parse_cotp(IsoConnection*, ByteBuffer*);

SessionIndication parse_session(IsoConnection*, ByteBuffer*);
SessionIndication parse_session_header_parameters(IsoConnection*, ByteBuffer*, u32);

int parse_presentation_user_data(IsoConnection*, ByteBuffer*);

int parse_mms(IsoConnection*, ByteBuffer*);

u32 merge_state(IsoConnection*);

#endif // _ISO_PARSE_TYPES_H
