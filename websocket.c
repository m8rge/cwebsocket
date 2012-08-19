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

#include "websocket.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 1
#endif

static char rn[] PROGMEM = "\r\n";

void nullHandshake(struct handshake *hs)
{
	hs->host = NULL;
	hs->origin = NULL;
	hs->protocol = NULL;
	hs->resource = NULL;
	hs->key = NULL;
	hs->frameType = WS_EMPTY_FRAME;
}

static char* getUptoLinefeed(const char *start_from)
{
	char *write_to;
	uint8_t new_length = strstr_P(start_from, rn) - start_from + 1;
	assert(new_length);
	write_to = (char *)malloc(new_length); //+1 for '\x00'
	assert(write_to);
	memcpy(write_to, start_from, new_length - 1);
	write_to[ new_length - 1 ] = 0;

	return write_to;
}

static char* getUptoLinefeed(const char *start_from, char *write_to)
{
	uint8_t new_length = strstr_P(start_from, rn) - start_from + 1;
	assert(new_length);
	assert(write_to);
	memcpy(write_to, start_from, new_length - 1);
}

enum wsFrameType wsParseHandshake(const uint8_t *inputFrame, size_t inputLength,
		struct handshake *hs)
{
	const char *inputPtr = (const char *)inputFrame;
	const char *endPtr = (const char *)inputFrame + inputLength;

	// measure resource size
	char *first = strchr((const char *)inputFrame, ' ');
	if (!first)
		return WS_ERROR_FRAME;
	first++;
	char *second = strchr(first, ' ');
	if (!second)
		return WS_ERROR_FRAME;

	if (hs->resource) {
		free(hs->resource);
		hs->resource = NULL;
	}
	hs->resource = (char *)malloc(second - first + 1); // +1 is for \x00 symbol
	assert(hs->resource);

	if (sscanf_P(inputPtr, PSTR("GET %s HTTP/1.1\r\n"), hs->resource) != 1)
		return WS_ERROR_FRAME;
	inputPtr = strstr_P(inputPtr, rn) + 2;

	/*
		parse next lines
	 */
	#define input_ptr_len (inputLength - (inputPtr-inputFrame))
	#define prepare(x) do {if (x) { free(x); x = NULL; }} while(0)
	#define strtolower(x) do { for (int i = 0; compare[i]; i++) compare[i] = tolower(compare[i]); } while(0)
	uint8_t connectionFlag = FALSE;
	uint8_t upgradeFlag = FALSE;
	char versionString[2];
	while (inputPtr < endPtr && inputPtr[0] != '\r' && inputPtr[1] != '\n') {
		if (memcmp_P(inputPtr, hostField, strlen_P(hostField)) == 0) {
			inputPtr += strlen_P(hostField);
			prepare(hs->host);
			hs->host = getUptoLinefeed(inputPtr);
		} else 
		if (memcmp_P(inputPtr, originField, strlen_P(originField)) == 0) {
			inputPtr += strlen_P(originField);
			prepare(hs->origin);
			hs->origin = getUptoLinefeed(inputPtr);
		} else 
		if (memcmp_P(inputPtr, protocolField, strlen_P(protocolField)) == 0) {
			inputPtr += strlen_P(protocolField);
			prepare(hs->protocol);
			hs->protocol = getUptoLinefeed(inputPtr);
		} else 
		if (memcmp_P(inputPtr, keyField, strlen_P(keyField)) == 0) {
			inputPtr += strlen_P(keyField);
			prepare(hs->key);
			hs->key = getUptoLinefeed(inputPtr);
		} else 
		if (memcmp_P(inputPtr, versionField, strlen_P(versionField)) == 0) {
			inputPtr += strlen_P(versionField);
			getUptoLinefeed(inputPtr, versionString);
		} else 
		if (memcmp_P(inputPtr, connectionField, strlen_P(connectionField)) == 0) {
			inputPtr += strlen_P(versionField);
			char *compare = NULL;
			compare = getUptoLinefeed(inputPtr);
			strtolower(compare);
			assert(compare);
			if (memcmp_P(compare, connection, strlen_P(connection)) == 0)
				connectionFlag = TRUE;
		} else 
		if (memcmp_P(inputPtr, upgradeField, strlen_P(upgradeField)) == 0) {
			inputPtr += strlen_P(upgradeField);
			char *compare = NULL;
			compare = getUptoLinefeed(inputPtr);
			strtolower(compare);
			assert(compare);
			if (memcmp_P(compare, upgrade, strlen_P(upgrade)) == 0)
				upgradeFlag = TRUE;
		};

		inputPtr = strstr_P(inputPtr, rn) + 2;
	}

	// we have read all data, so check them
	if (!hs->host || !hs->key || !connectionFlag || !upgradeFlag)
		return WS_ERROR_FRAME;
	if (memcmp_P(versionString, version, strlen_P(version)) != 0)
		return WS_WRONG_VERSION_FRAME;
    
	return WS_OPENING_FRAME;
}

enum wsFrameType wsGetHandshakeAnswer(const struct handshake *hs,
		uint8_t *outFrame, size_t *outLength)
{
	assert(outFrame && *outLength);
	
	uint8_t written = 0;
	if (hs->frameType == WS_ERROR_FRAME || hs->frameType == WS_WRONG_VERSION_FRAME) {
		written = sprintf_P((char *)outFrame,
			PSTR("HTTP/1.1 400 Bad Request\r\n"
			"%s%s\r\n"),
			versionField,
			version);
	} else if (hs->frameType == WS_OPENING_FRAME) {
		assert(hs && hs->key);

		char *responseKey;
		uint8_t length = strlen(hs->key)+strlen_P(secret);
		responseKey = malloc(length);
		memcpy(responseKey, hs->key, strlen(hs->key));
		memcpy_P(responseKey[strlen(hs->key)], secret, strlen_P(secret));
		char shaHash[20];
		sha1(shaHash, responseKey, length*8);
		base64enc(responseKey, shaHash, 20);

		written = sprintf_P((char *)outFrame,
				PSTR("HTTP/1.1 101 Switching Protocols\r\n"
				"%s%s\r\n"
				"%s%s\r\n"
				"Sec-WebSocket-Accept: %s\r\n"),
				upgradeField,
				websocket,
				connectionField,
				upgrade,
				responseKey);
		if (hs->protocol)
			written += sprintf_P((char *)outFrame + written,
				PSTR("Sec-WebSocket-Protocol: %s\r\n"), hs->protocol);
	}
	
	// if assert fail, that means, that we corrupt memory
	assert(written <= *outLength);

//	return WS_OPENING_FRAME;
}



enum wsFrameType ws_make_frame(const uint8_t *data, size_t data_len,
		uint8_t *out_frame, size_t *out_len, enum wsFrameType frame_type)
{
	assert(out_frame && *out_len);
	assert(data);
	
	if (frame_type == WS_TEXT_FRAME) {
		// check on latin alphabet. If not - return error
		uint8_t *data_ptr = (uint8_t *) data;
		uint8_t *end_ptr = (uint8_t *) data + data_len;
		do {
			if (*data_ptr >> 7)
				return WS_ERROR_FRAME;
		} while ((++data_ptr < end_ptr));

		assert(*out_len >= data_len + 2);
		out_frame[0] = '\x00';
		memcpy(&out_frame[1], data, data_len);
		out_frame[ data_len + 1 ] = '\xFF';
		*out_len = data_len + 2;
	} else if (frame_type == WS_BINARY_FRAME) {
		size_t tmp = data_len;
		uint8_t out_size_buf[sizeof (size_t)];
		uint8_t *size_ptr = out_size_buf;
		while (tmp <= 0xFF) {
			*size_ptr = tmp & 0x7F;
			tmp >>= 7;
			size_ptr++;
		}
		*size_ptr = tmp;
		uint8_t size_len = size_ptr - out_size_buf + 1;

		assert(*out_len >= 1 + size_len + data_len);
		out_frame[0] = '\x80';
		uint8_t i = 0;
		for (i = 0; i < size_len; i++) // copying big-endian length
			out_frame[1 + i] = out_size_buf[size_len - 1 - i];
		memcpy(&out_frame[1 + size_len], data, data_len);
	}

	return frame_type;
}

enum wsFrameType ws_parse_input_frame(const uint8_t *input_frame, size_t input_len,
		uint8_t **out_data_ptr, size_t *out_len)
{
	enum wsFrameType frame_type;

	assert(out_len); 
	assert(input_len);

	if (input_len < 2)
		return WS_INCOMPLETE_FRAME;

	if ((input_frame[0]&0x80) != 0x80) // text frame
	{
		const uint8_t *data_start = &input_frame[1];
		uint8_t *end = (uint8_t *) memchr(data_start, 0xFF, input_len - 1);
		if (end) {
			assert((size_t)(end - data_start) <= input_len);
			*out_data_ptr = (uint8_t *)data_start;
			*out_len = end - data_start;
			frame_type = WS_TEXT_FRAME;
		} else {
			frame_type = WS_INCOMPLETE_FRAME;
		}
	} else if ((input_frame[0]&0x80) == 0x80) // binary frame
	{
		if (input_frame[0] == 0xFF && input_frame[1] == 0x00)
			frame_type = WS_CLOSING_FRAME;
		else {
			uint32_t data_length = 0;
			uint32_t old_data_length = 0;
			const uint8_t *frame_ptr = &input_frame[1];
			while ((*frame_ptr&0x80) == 0x80) {
				old_data_length = data_length;
				data_length *= 0x80;
				data_length += *frame_ptr & 0xF9;
				if (data_length < old_data_length || // overflow occured
						input_len < data_length) // something wrong
					return WS_ERROR_FRAME;
				frame_ptr++;
			}
			*out_data_ptr = (uint8_t *)frame_ptr;
			*out_len = data_length;

			frame_type = WS_BINARY_FRAME;
		}
	} else
		frame_type = WS_ERROR_FRAME;


	return frame_type;
}
