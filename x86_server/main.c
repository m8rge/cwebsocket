/*
 * Copyright (c) 2014 Putilov Andrey
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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "websocket.h"

#define PORT 8088
#define BUF_LEN 0xFFFF
#define PACKET_DUMP

uint8_t gBuffer[BUF_LEN];

void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int safeSend(int clientSocket, const uint8_t *buffer, size_t bufferSize)
{
    #ifdef PACKET_DUMP
    printf("out packet:\n");
    fwrite(buffer, 1, bufferSize, stdout);
    printf("\n");
    #endif
    ssize_t written = send(clientSocket, buffer, bufferSize, 0);
    if (written == -1) {
        close(clientSocket);
        perror("send failed");
        return EXIT_FAILURE;
    }
    if (written != bufferSize) {
        close(clientSocket);
        perror("written not all bytes");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

void clientWorker(int clientSocket)
{
    memset(gBuffer, 0, BUF_LEN);
    size_t readedLength = 0;
    size_t frameSize = BUF_LEN;
    enum wsState state = WS_STATE_OPENING;
    uint8_t *data = NULL;
    size_t dataSize = 0;
    enum wsFrameType frameType = WS_INCOMPLETE_FRAME;
    struct handshake hs;
    nullHandshake(&hs);
    
    #define prepareBuffer frameSize = BUF_LEN; memset(gBuffer, 0, BUF_LEN);
    #define initNewFrame frameType = WS_INCOMPLETE_FRAME; readedLength = 0; memset(gBuffer, 0, BUF_LEN);
    
    while (frameType == WS_INCOMPLETE_FRAME) {
        ssize_t readed = recv(clientSocket, gBuffer+readedLength, BUF_LEN-readedLength, 0);
        if (!readed) {
            close(clientSocket);
            perror("recv failed");
            return;
        }
        #ifdef PACKET_DUMP
        printf("in packet:\n");
        fwrite(gBuffer, 1, readed, stdout);
        printf("\n");
        #endif
        readedLength+= readed;
        assert(readedLength <= BUF_LEN);
        
        if (state == WS_STATE_OPENING) {
            frameType = wsParseHandshake(gBuffer, readedLength, &hs);
        } else {
            frameType = wsParseInputFrame(gBuffer, readedLength, &data, &dataSize);
        }
        
        if ((frameType == WS_INCOMPLETE_FRAME && readedLength == BUF_LEN) || frameType == WS_ERROR_FRAME) {
            if (frameType == WS_INCOMPLETE_FRAME)
                printf("buffer too small");
            else
                printf("error in incoming frame\n");
            
            if (state == WS_STATE_OPENING) {
                prepareBuffer;
                frameSize = sprintf((char *)gBuffer,
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "%s%s\r\n\r\n",
                                    versionField,
                                    version);
                safeSend(clientSocket, gBuffer, frameSize);
                break;
            } else {
                prepareBuffer;
                wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
                if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
                    break;
                state = WS_STATE_CLOSING;
                initNewFrame;
            }
        }
        
        if (state == WS_STATE_OPENING) {
            assert(frameType == WS_OPENING_FRAME);
            if (frameType == WS_OPENING_FRAME) {
                // if resource is right, generate answer handshake and send it
                if (strcmp(hs.resource, "/echo") != 0) {
                    frameSize = sprintf((char *)gBuffer, "HTTP/1.1 404 Not Found\r\n\r\n");
                    safeSend(clientSocket, gBuffer, frameSize);
                    break;
                }
                
                prepareBuffer;
                wsGetHandshakeAnswer(&hs, gBuffer, &frameSize);
                freeHandshake(&hs);
                if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
                    break;
                state = WS_STATE_NORMAL;
                initNewFrame;
            }
        } else {
            if (frameType == WS_CLOSING_FRAME) {
                if (state == WS_STATE_CLOSING) {
                    break;
                } else {
                    prepareBuffer;
                    wsMakeFrame(NULL, 0, gBuffer, &frameSize, WS_CLOSING_FRAME);
                    safeSend(clientSocket, gBuffer, frameSize);
                    break;
                }
            } else if (frameType == WS_TEXT_FRAME) {
                uint8_t *recievedString = NULL;
                recievedString = malloc(dataSize+1);
                assert(recievedString);
                memcpy(recievedString, data, dataSize);
                recievedString[ dataSize ] = 0;
                
                prepareBuffer;
                wsMakeFrame(recievedString, dataSize, gBuffer, &frameSize, WS_TEXT_FRAME);
                free(recievedString);
                if (safeSend(clientSocket, gBuffer, frameSize) == EXIT_FAILURE)
                    break;
                initNewFrame;
            }
        }
    } // read/write cycle
    
    close(clientSocket);
}

int main(int argc, char** argv)
{
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == -1) {
        error("create socket failed");
    }
    
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(PORT);
    if (bind(listenSocket, (struct sockaddr *) &local, sizeof(local)) == -1) {
        error("bind failed");
    }
    
    if (listen(listenSocket, 1) == -1) {
        error("listen failed");
    }
    printf("opened %s:%d\n", inet_ntoa(local.sin_addr), ntohs(local.sin_port));
    
    while (TRUE) {
        struct sockaddr_in remote;
        socklen_t sockaddrLen = sizeof(remote);
        int clientSocket = accept(listenSocket, (struct sockaddr*)&remote, &sockaddrLen);
        if (clientSocket == -1) {
            error("accept failed");
        }
        
        printf("connected %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
        clientWorker(clientSocket);
        printf("disconnected\n");
    }
    
    close(listenSocket);
    return EXIT_SUCCESS;
}

