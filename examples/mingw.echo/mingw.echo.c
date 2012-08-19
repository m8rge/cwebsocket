/*
 * Copyright (c) 2010 Putilov Andrey
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <winsock.h>
#include "md5.c"
#include "websocket.c"

#define PORT 8080
#define BUF_LEN 0x1FF
#define PACKET_DUMP

int terminate = FALSE;

int client_worker(SOCKET clientsocket)
{
	static uint8_t buffer[BUF_LEN];
	size_t readed_length = 0;
	size_t out_len = BUF_LEN;
	int written = 0;
	enum wsFrameType frame_type = WS_INCOMPLETE_FRAME;
	struct handshake hs;
	nullHandshake(&hs);

	// read openinig handshake
	while (frame_type == WS_INCOMPLETE_FRAME) {
		int readed = recv(clientsocket, buffer+readed_length, BUF_LEN-readed_length, 0);
		if (!readed) {
			fprintf(stderr, "Recv failed: %d\n", WSAGetLastError());
			closesocket(clientsocket);
			return EXIT_FAILURE;
		}
		#ifdef PACKET_DUMP
			printf("In packet:\n");
			fwrite(buffer, 1, readed, stdout);
			printf("\n");
		#endif
		readed_length+= readed;
		assert(readed_length <= BUF_LEN);
		frame_type = wsParseHandshake(buffer, readed_length, &hs);
		if (frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN) {
			fprintf(stderr, "Buffer too small\n");
			closesocket(clientsocket);
			return EXIT_FAILURE;
		} else
		if (frame_type == WS_ERROR_FRAME) {
			fprintf(stderr, "Error in incoming frame\n");
			closesocket(clientsocket);
			return EXIT_FAILURE;
		}
	}
	assert(frame_type == WS_OPENING_FRAME);

	// if resource is right, generate answer handshake and send it
	if (strcmp(hs.resource, "/echo") != 0) {
		fprintf(stderr, "Resource is wrong:%s\n", hs.resource);
		closesocket(clientsocket);
		return EXIT_FAILURE;
	}
	out_len = BUF_LEN;
	ws_get_handshake_answer(&hs, buffer, &out_len);
	#ifdef PACKET_DUMP
		printf("Out packet:\n");
		fwrite(buffer, 1, out_len, stdout);
		printf("\n");
	#endif
	written = send(clientsocket, buffer, out_len, 0);
	if (written == SOCKET_ERROR) {
		fprintf(stderr, "Send failed: %d\n", WSAGetLastError());
		closesocket(clientsocket);
		return EXIT_FAILURE;
	}
	if (written != out_len) {
		fprintf(stderr, "Written %d of %d\n", written, out_len);
		closesocket(clientsocket);
		return EXIT_FAILURE;
	}
	
	// connect success!
	// read incoming packet and parse it;
	readed_length = 0;
	frame_type = WS_INCOMPLETE_FRAME;
	while (frame_type == WS_INCOMPLETE_FRAME) {
		int readed = recv(clientsocket, buffer+readed_length, BUF_LEN-readed_length, 0);
		if (!readed) {
			fprintf(stderr, "Recv failed: %d\n", WSAGetLastError());
			closesocket(clientsocket);
			return EXIT_FAILURE;
		}
		#ifdef PACKET_DUMP
			printf("In packet:\n");
			fwrite(buffer, 1, readed, stdout);
			printf("\n");
		#endif
		readed_length+= readed;
		assert(readed_length <= BUF_LEN);
		size_t data_len;
		uint8_t *data;
		frame_type = ws_parse_input_frame(buffer, readed_length, &data, &data_len);
		if (frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN) {
			fprintf(stderr, "Buffer too small\n");
			closesocket(clientsocket);
			return EXIT_FAILURE;
		} else
		if (frame_type == WS_CLOSING_FRAME) {
			send(clientsocket, "\xFF\x00", 2, 0); // send closing frame
			closesocket(clientsocket); // and close connection
			break;
		} else
		if (frame_type == WS_ERROR_FRAME) {
			fprintf(stderr, "Error in incoming frame\n");
			closesocket(clientsocket);
			return EXIT_FAILURE;
		} else
		if (frame_type == WS_TEXT_FRAME) {
			out_len = BUF_LEN;
			frame_type = ws_make_frame(data, data_len, buffer, &out_len, WS_TEXT_FRAME);
			if (frame_type != WS_TEXT_FRAME) {
				fprintf(stderr, "Make frame failed\n");
				closesocket(clientsocket);
				return EXIT_FAILURE;
			}
			#ifdef PACKET_DUMP
				printf("Out packet:\n");
				fwrite(buffer, 1, out_len, stdout);
				printf("\n");
			#endif
			written = send(clientsocket, buffer, out_len, 0);
			if (written == SOCKET_ERROR) {
				fprintf(stderr, "Send failed: %d\n", WSAGetLastError());
				closesocket(clientsocket);
				return EXIT_FAILURE;
			}
			if (written != out_len) {
				fprintf(stderr, "Written %d of %d\n", written, out_len);
				closesocket(clientsocket);
				return EXIT_FAILURE;
			}
			readed_length = 0;
			frame_type = WS_INCOMPLETE_FRAME;
		}
	} // read/write cycle

	closesocket(clientsocket);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv)
{
	WSADATA data;
	int result = WSAStartup(MAKEWORD(2, 2), &data);
	if (result != 0) {
		fprintf(stderr, "Error in WSAStartup\n");
		return EXIT_FAILURE;
	}

	SOCKET listensocket = socket(AF_INET,SOCK_STREAM, 0);
	if (listensocket == INVALID_SOCKET) {
		fprintf(stderr, "Create socket failed: %ld\n", WSAGetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(PORT);
	result = bind(listensocket, (struct sockaddr*)&local, sizeof(local));
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "Bind failed: %ld\n", WSAGetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	result = listen(listensocket, 1);
	if (result == SOCKET_ERROR) {
		fprintf(stderr, "Listen failed: %ld\n", WSAGetLastError());
		return EXIT_FAILURE;
	}

	printf("Server started at localhost:%d...\n", PORT);

	while (!terminate) {
		struct sockaddr_in remote;
		int sockaddr_len = sizeof(remote);
		SOCKET clientsocket = accept(listensocket, (struct sockaddr*)&remote, &sockaddr_len);
		if (clientsocket == INVALID_SOCKET) {
			fprintf(stderr, "Accept failed: %d\n", WSAGetLastError());
			return EXIT_FAILURE;
		}

		printf("Connected %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
		client_worker(clientsocket);
		printf("Disconnected\n");
	}

	closesocket(listensocket);
	WSACleanup();
	return (EXIT_SUCCESS);
}

