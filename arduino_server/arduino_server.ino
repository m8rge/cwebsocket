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
 
//#define DEBUG
#define BUF_LEN 300
#include <Ethernet.h>

// this define need to be placed before WebSocket.h!
#ifdef DEBUG
  #define __ASSERT_USE_STDERR
#endif
#include <websocket.h>

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
byte ip[] = { 192, 168, 0, 4 };
Server server(8080);

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

int clientWorker(Client client)
{
  static uint8_t buffer[BUF_LEN];
  uint8_t *bufPointer = buffer;
  enum ws_frame_type frame_type = WS_INCOMPLETE_FRAME;
  struct handshake hs;
  nullhandshake(&hs);

  #ifdef DEBUG
    printf_P(PSTR("New client connected\n"));
  #endif
  
  #define terminate() client.stop(); return 1
  // read openinig handshake
  while (frame_type == WS_INCOMPLETE_FRAME) {
    while (client.available() && bufPointer <= &buffer[BUF_LEN]) {
      *bufPointer++ = client.read();
    }
    size_t readed_length = bufPointer-buffer;
    
    #ifdef DEBUG
      printf_P(PSTR("ws_parse_handshake with frame(%d):\n"), readed_length);
      fwrite(buffer, 1, readed_length, stdout);
      printf_P(PSTR("\n"));
    #endif
    frame_type = ws_parse_handshake(buffer, readed_length, &hs);
    if (frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN) {
      #ifdef DEBUG
        fprintf_P(stderr, PSTR("Buffer too small\n"));
      #endif
      terminate();
    } else
    if (frame_type == WS_ERROR_FRAME) {
      #ifdef DEBUG
        fprintf_P(stderr, PSTR("Error in incoming frame\n"));
      #endif
      terminate();
    }
  }
  assert(frame_type == WS_OPENING_FRAME);

  if (strcmp_P(hs.resource, PSTR("/echo")) != 0) {
    #ifdef DEBUG
      fprintf_P(stderr, PSTR("Resource is wrong:%s\n"), hs.resource);
    #endif
    terminate();
  }
  
  size_t out_len = BUF_LEN;
  ws_get_handshake_answer(&hs, buffer, &out_len);
  #ifdef DEBUG
    printf_P(PSTR("Write frame:\n"));
    fwrite(buffer, 1, out_len, stdout);
    printf_P(PSTR("\n"));
  #endif
  client.write(buffer, out_len);
  
  if (client.connected()) { // we are establish websocket connection
    bufPointer = buffer;
    frame_type = WS_INCOMPLETE_FRAME;
    while (frame_type == WS_INCOMPLETE_FRAME) {
      while (!client.available() && client.connected()) {}; // wait for data
      if (!client.connected()) { // client disconnected
        terminate();
      }
      while (client.available() && bufPointer <= &buffer[BUF_LEN]) {
        *bufPointer++ = client.read();
      }
      size_t readed_length = bufPointer-buffer;
      
      #ifdef DEBUG
        printf_P(PSTR("ws_parse_input_frame with frame(%d):\n"), readed_length);
        fwrite(buffer, 1, readed_length, stdout);
        printf_P(PSTR("\n"));
      #endif
      uint8_t *data;
      size_t data_len = BUF_LEN;
      frame_type = ws_parse_input_frame(buffer, readed_length, &data, &data_len);
      if (frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN) {
        #ifdef DEBUG
          fprintf_P(stderr, PSTR("Buffer too small\n"));
        #endif
        terminate();
      } else
      if (frame_type == WS_ERROR_FRAME) {
        #ifdef DEBUG
          fprintf_P(stderr, PSTR("Error in incoming frame\n"));
        #endif
        terminate();
      } else
      if (frame_type == WS_CLOSING_FRAME) {
        #ifdef DEBUG
          printf_P(PSTR("Get closing frame\n"));
        #endif
        client.write((uint8_t *)"\xFF\x00", 2);
        break;
      } else
      if (frame_type == WS_TEXT_FRAME) {
        #ifdef DEBUG
          fprintf_P(stderr, PSTR("Get text frame(%d):\n"), data_len);
          fwrite(data, 1, data_len, stdout);
          printf_P(PSTR("\n"));
        #endif
        out_len = BUF_LEN;
        frame_type = ws_make_frame(data, data_len, buffer, &out_len, WS_TEXT_FRAME);
        if (frame_type != WS_TEXT_FRAME) {
          #ifdef DEBUG
            fprintf_P(stderr, PSTR("Make frame failed\n"));
          #endif
          terminate();
        }
        client.write(buffer, out_len);
        
        bufPointer = buffer;
        frame_type = WS_INCOMPLETE_FRAME;
      }
    } // while (frame_type == WS_INCOMPLETE_FRAME) / read new frame
  } // client.connected / if handshake success

  client.stop();
  return 0;
}

void loop()
{
  Client client = server.available();
  if (client) {
    clientWorker(client);
    #ifdef DEBUG
      printf_P(PSTR("Disconnected\n"));
    #endif
  }
}
