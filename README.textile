## Overview
cWebsocket is lightweight websocket server library written in C. This library include functions for easy creating websocket server. It implements [websocket protocol draft 76](http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76).

## Features
This library consist of one main cwebsocket.c file and md5 implementation files.  
It very easy to embed in any your application at any platform.  
Library design was made with microcontrollers architecture in mind.  

## Microcontrollers
With this library you can get realtime properties from your microcontroller only with browser! Currently we have arduino support.

## Notes
### Not supported
* frames with raw data (implemented, but not tested)
* non-latin characters in text frames

### Browser support
Google Chrome 6 (up to 6.0.472.0) doesn't have disconnect sequence. It just drops connection on `javascript:WebSocket.close()` method.