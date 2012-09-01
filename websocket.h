/*
 * Copyright (c) 2012 Putilov Andrey
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#ifndef WEBSOCKET_H
#define	WEBSOCKET_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h> /* uint8_t */
#include <stdlib.h> /* strtoul */
#include <string.h>
#include <stdio.h> /* sscanf */
#include <ctype.h> /* isdigit */
#include <stddef.h> /* size_t */
#include "base64_enc.h"
#include "sha1.h"
#ifdef __AVR__
	#include <avr/pgmspace.h>
#else
	#define PROGMEM
	#define PSTR
	#define strstr_P strstr
	#define sscanf_P sscanf
	#define sprintf_P sprintf
	#define strlen_P strlen
	#define memcmp_P memcmp
	#define memcpy_P memcpy
#endif

static const char connectionField[] PROGMEM = "Connection: ";
static const char upgrade[] PROGMEM = "upgrade";
static const char upgradeField[] PROGMEM = "Upgrade: ";
static const char websocket[] PROGMEM = "websocket";
static const char hostField[] PROGMEM = "Host: ";
static const char originField[] PROGMEM = "Origin: ";
static const char keyField[] PROGMEM = "Sec-WebSocket-Key: ";
static const char protocolField[] PROGMEM = "Sec-WebSocket-Protocol: ";
static const char versionField[] PROGMEM = "Sec-WebSocket-Version: ";
static const char version[] PROGMEM = "13";
static const char secret[] PROGMEM = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

enum wsFrameType {
	WS_EMPTY_FRAME,
	WS_ERROR_FRAME,
	WS_INCOMPLETE_FRAME,
	WS_TEXT_FRAME,
	WS_BINARY_FRAME,
	WS_PING_FRAME,
	WS_PONG_FRAME,
	WS_OPENING_FRAME,
	WS_CLOSING_FRAME
};

struct handshake {
	char *host;
	char *origin;
	char *key;
	char *protocol;
	char *resource;
	enum frameType;
};

	/**
	 *
	 * @param input_frame .in. pointer to input frame
	 * @param input_len .in. length of input frame
	 * @param hs .out. clear with nullhandshake() handshake struct
	 * @return [WS_INCOMPLETE_FRAME, WS_ERROR_FRAME, WS_OPENING_FRAME]
	 */

	enum wsFrameType wsParseHandshake(const uint8_t *input_frame, size_t input_len,
		struct handshake *hs);
	
	/**
	 *
	 * @param hs .in. filled handshake struct
	 * @param out_frame .out. pointer to out frame buffer
	 * @param out_len .in.out. length of out frame buffer. Return length of out frame
	 */
	void wsGetHandshakeAnswer(const struct handshake *hs,
		uint8_t *out_frame, size_t *out_len);

	/**
	 *
	 * @param data .in. pointer to input data array
	 * @param data_len .in. length of data array
	 * @param out_frame .out. pointer to out frame buffer
	 * @param out_len .in.out. length of out frame buffer. Return length of out frame
	 * @param frame_type .in. [WS_TEXT_FRAME] frame type to build
	 * @return [WS_ERROR_FRAME, WS_TEXT_FRAME]
	 */
	enum wsFrameType ws_make_frame(const uint8_t *data, size_t data_len,
		uint8_t *out_frame, size_t *out_len, enum wsFrameType frame_type);

	/**
	 *
	 * @param inputFrame .in. pointer to input frame
	 * @param inputLen .in. length of input frame
	 * @param outDataPtr .out. pointer to extracted data in input frame
	 * @param outLen .in.out. length of out data buffer. Return length of extracted data
	 * @return [WS_INCOMPLETE_FRAME, WS_TEXT_FRAME, WS_CLOSING_FRAME, WS_ERROR_FRAME]
	 */
	enum wsFrameType wsParseInputFrame(const uint8_t *inputFrame, size_t inputLen,
		uint8_t *outDataPtr, size_t *outLen);

	/**
	 *
	 * @param hs .out. nulled handshake struct
	 */
	void nullHandshake(struct handshake *hs);

#ifdef	__cplusplus
}
#endif

#endif	/* WEBSOCKET_H */

