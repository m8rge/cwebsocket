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

#define BUF_LEN 300
#include <Ethernet.h>
#include <WebSocket.h>

byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
byte ip[] = { 192, 168, 0, 4 };
Server server(8080);

void setup()
{
  Ethernet.begin(mac, ip);
  server.begin();
}

int clientWorker(Client client)
{
  static uint8_t buffer[BUF_LEN];
  uint8_t *bufPointer = buffer;
  enum ws_frame_type frame_type = WS_INCOMPLETE_FRAME;
  struct handshake hs;
  nullhandshake(&hs);

  #define check_error(x) if (x) {client.stop(); return 1;}
  // read openinig handshake
  while (frame_type == WS_INCOMPLETE_FRAME) {
    while (client.available() && bufPointer <= &buffer[BUF_LEN]) {
      *bufPointer++ = client.read();
    }
    size_t readed_length = bufPointer-buffer;
    
    frame_type = ws_parse_handshake(buffer, readed_length, &hs);
    check_error(frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN 
      || frame_type == WS_ERROR_FRAME);
  }

  // filter resource to "/echo"
  check_error(strcmp_P(hs.resource, PSTR("/echo")) != 0);
  
  size_t out_len = BUF_LEN;
  ws_get_handshake_answer(&hs, buffer, &out_len);
  client.write(buffer, out_len);
  
  if (client.connected()) { // we are establish websocket connection
    bufPointer = buffer;
    frame_type = WS_INCOMPLETE_FRAME;
    while (frame_type == WS_INCOMPLETE_FRAME) {
      while (!client.available() && client.connected()) {}; // wait for data
      check_error(!client.connected()); // client disconnected
      while (client.available() && bufPointer <= &buffer[BUF_LEN]) {
        *bufPointer++ = client.read();
      }
      size_t readed_length = bufPointer-buffer;
      
      uint8_t *data;
      size_t data_len = BUF_LEN;
      frame_type = ws_parse_input_frame(buffer, readed_length, &data, &data_len);
      check_error(frame_type == WS_INCOMPLETE_FRAME && readed_length == BUF_LEN
          || frame_type == WS_ERROR_FRAME);
      if (frame_type == WS_CLOSING_FRAME) {
        client.write((uint8_t *)"\xFF\x00", 2);
        break;
      } else
      if (frame_type == WS_TEXT_FRAME) {
        out_len = BUF_LEN;
        frame_type = ws_make_frame(data, data_len, buffer, &out_len, WS_TEXT_FRAME);
        check_error(frame_type != WS_TEXT_FRAME);
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
  }
}
