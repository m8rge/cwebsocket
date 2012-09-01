## Overview
cWebsocket is lightweight websocket server library written in C. This library include functions for easy creating websocket server. It implements [websocket protocol rfc6455](http://tools.ietf.org/html/rfc6455).

## Features
Pure C.  
It's tiny!  
It very easy to embed in any your application at any platform.  
Library design was made with microcontrollers architecture in mind.  

## Microcontrollers
With this library you can get realtime properties from your microcontroller only with browser! Currently we have arduino support.

## Notes
### Not supported
* frames with raw data (implemented, but not tested)
* non-latin characters in text frames
* websocket extensions
* cookies
* continuation frame (all payload data length must be encapsulated into one frame)