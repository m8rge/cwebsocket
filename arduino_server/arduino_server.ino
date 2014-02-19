/*
 * Copyright (c) 2013 Putilov Andrey
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

#define DEBUG
#define PORT 8088
#define BUF_LEN 0xFF
#ifdef DEBUG
  #define __ASSERT_USE_STDERR
#endif

#include <SPI.h>
#include <Ethernet.h>
#include <websocket.h>

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
IPAddress ip(192, 168, 0, 4);
EthernetServer server(PORT);

int serialWrite(char c, FILE *f) {
  Serial.write(c);
  return 0;
}

void setup()
{
  Ethernet.begin(mac, ip);
  server.begin();
  #ifdef DEBUG
    Serial.begin(9600);
    stdout = stderr = fdevopen(serialWrite, NULL);
    printf_P(PSTR("Server started. waiting for clients...\n"));
  #endif
}

void sendAndLog(EthernetClient client, const uint8_t *buffer, size_t bufferSize)
{
  client.write(buffer, bufferSize);
  #ifdef DEBUG
  printf_P(PSTR("out packet:\n"));
  fwrite(buffer, 1, bufferSize, stdout);
  printf_P(PSTR("\n"));
  #endif
}

void clientWorker(EthernetClient client)
{
  uint8_t buffer[BUF_LEN];
  memset(buffer, 0, BUF_LEN);
  size_t readedLength = 0;
  size_t frameSize = BUF_LEN;
  enum wsState state = WS_STATE_OPENING;
  uint8_t *data = NULL;
  size_t dataSize = 0;
  enum wsFrameType frameType = WS_INCOMPLETE_FRAME;
  struct handshake hs;
  nullHandshake(&hs);
  
  #define prepareBuffer frameSize = BUF_LEN; memset(buffer, 0, BUF_LEN);
  #define initNewFrame frameType = WS_INCOMPLETE_FRAME; readedLength = 0; memset(buffer, 0, BUF_LEN);
  
  while (frameType == WS_INCOMPLETE_FRAME && client.connected()) {
    while (client.available() && readedLength <= BUF_LEN) {
      buffer[readedLength++] = client.read();
    }
    #ifdef DEBUG
    printf("in packet:\n");
    fwrite(buffer, 1, readedLength, stdout);
    printf("\n");
    #endif
    assert(readedLength <= BUF_LEN);

    if (state == WS_STATE_OPENING) {
      frameType = wsParseHandshake(buffer, readedLength, &hs);
    } else {
      frameType = wsParseInputFrame(buffer, readedLength, &data, &dataSize);
    }
    
    if ((frameType == WS_INCOMPLETE_FRAME && readedLength == BUF_LEN) || frameType == WS_ERROR_FRAME) {
      #ifdef DEBUG
      if (frameType == WS_INCOMPLETE_FRAME)
        printf_P(PSTR("buffer too small"));
      else
        printf_P(PSTR("error in incoming frame\n"));
    #endif
      
      if (state == WS_STATE_OPENING) {
        prepareBuffer;
        frameSize = sprintf_P((char *)buffer,
                            PSTR("HTTP/1.1 400 Bad Request\r\n"
                            "%s%s\r\n\r\n"),
                            versionField,
                            version);
        sendAndLog(client, buffer, frameSize);
        break;
      } else {
        prepareBuffer;
        wsMakeFrame(NULL, 0, buffer, &frameSize, WS_CLOSING_FRAME);
        sendAndLog(client, buffer, frameSize);
        state = WS_STATE_CLOSING;
        initNewFrame;
      }
    }
    
    if (state == WS_STATE_OPENING) {
      assert(frameType == WS_OPENING_FRAME);
      if (frameType == WS_OPENING_FRAME) {
        // if resource is right, generate answer handshake and send it
        if (strcmp(hs.resource, "/echo") != 0) {
          frameSize = sprintf_P((char *)buffer, PSTR("HTTP/1.1 404 Not Found\r\n\r\n"));
          sendAndLog(client, buffer, frameSize);
        }
    
        prepareBuffer;
        wsGetHandshakeAnswer(&hs, buffer, &frameSize);
        freeHandshake(&hs);
        sendAndLog(client, buffer, frameSize);
        state = WS_STATE_NORMAL;
        initNewFrame;
      }
    } else {
        if (frameType == WS_CLOSING_FRAME) {
          if (state == WS_STATE_CLOSING) {
            break;
          } else {
            prepareBuffer;
            wsMakeFrame(NULL, 0, buffer, &frameSize, WS_CLOSING_FRAME);
            sendAndLog(client, buffer, frameSize);
            break;
          }
        } else if (frameType == WS_TEXT_FRAME) {
          uint8_t *recievedString = NULL;
          recievedString = (uint8_t *)malloc(dataSize+1);
          assert(recievedString);
          memcpy(recievedString, data, dataSize);
          recievedString[ dataSize ] = 0;
          
          prepareBuffer;
          wsMakeFrame(recievedString, dataSize, buffer, &frameSize, WS_TEXT_FRAME);
          free(recievedString);
          sendAndLog(client, buffer, frameSize);
          initNewFrame;
        }
    }
  } // read/write cycle
  
  client.stop();
}

void loop()
{
  EthernetClient client = server.available();
  if (client) {
    #ifdef DEBUG
      printf_P(PSTR("connected\n"));
    #endif
    clientWorker(client);
    #ifdef DEBUG
      printf_P(PSTR("disconnected\n"));
    #endif
  }
}
