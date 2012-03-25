/*
 * Copyright (c) 2010 Putilov Andrey
 *
 * Permission is hereby granted, free of uint8_tge, to any person obtaining a copy
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
#include "md5.h"
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
#endif

static const char connection[] PROGMEM = "Connection: Upgrade";
static const char upgrade[] PROGMEM = "Upgrade: WebSocket";
static const char host[] PROGMEM = "Host: ";
static const char origin[] PROGMEM = "Origin: ";
static const char protocol[] PROGMEM = "Sec-WebSocket-Protocol: ";
static const char key1[] PROGMEM = "Sec-WebSocket-Key1: ";
static const char key2[] PROGMEM = "Sec-WebSocket-Key2: ";

enum ws_frame_type {
	WS_ERROR_FRAME,
	WS_INCOMPLETE_FRAME,
	WS_TEXT_FRAME,
	WS_BINARY_FRAME,
	WS_OPENING_FRAME,
	WS_CLOSING_FRAME
};

struct handshake {
	char *resource;
	char *host;
	char *origin;
	char *protocol;
	char *key1;
	char *key2;
	char key3[8];
};

	/**
	 *
	 * @param input_frame .in. pointer to input frame
	 * @param input_len .in. length of input frame
	 * @param hs .out. clear with nullhandshake() handshake struct
	 * @return [WS_INCOMPLETE_FRAME, WS_ERROR_FRAME, WS_OPENING_FRAME]
	 */
	enum ws_frame_type ws_parse_handshake(const uint8_t *input_frame, size_t input_len,
		struct handshake *hs);

	/**
	 *
	 * @param hs .in. filled handshake struct
	 * @param out_frame .out. pointer to out frame buffer
	 * @param out_len .in.out. length of out frame buffer. Return length of out frame
	 * @return WS_OPENING_FRAME
	 */
	enum ws_frame_type ws_get_handshake_answer(const struct handshake *hs,
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
	enum ws_frame_type ws_make_frame(const uint8_t *data, size_t data_len,
		uint8_t *out_frame, size_t *out_len, enum ws_frame_type frame_type);

	/**
	 *
	 * @param input_frame .in. pointer to input frame
	 * @param input_len .in. length of input frame
	 * @param out_data_ptr .out. pointer to extracted data in input frame
	 * @param out_len .in.out. length of out data buffer. Return length of extracted data
	 * @return [WS_INCOMPLETE_FRAME, WS_TEXT_FRAME, WS_CLOSING_FRAME, WS_ERROR_FRAME]
	 */
	enum ws_frame_type ws_parse_input_frame(const uint8_t *input_frame, size_t input_len,
		uint8_t **out_data_ptr, size_t *out_len);

	/**
	 *
	 * @param hs .out. nulled handshake struct
	 */
	void nullhandshake(struct handshake *hs);

#ifdef	__cplusplus
}
#endif

#endif	/* WEBSOCKET_H */

