## Overview
cWebsocket is lightweight websocket server library written in C. This library include functions for easy creating websocket server. It implements [websocket protocol rfc6455](http://tools.ietf.org/html/rfc6455).

## Features
Pure C.  
It's tiny!  
It very easy to embed in any your application at any platform.  
Library design was made with microcontrollers architecture in mind.  
MIT Licensed.

## Microcontrollers
With this library you can turn your Arduino to websocket server and get realtime properties from your microcontroller only with browser!

## Notes
### Not supported
* [secure websocket](http://tools.ietf.org/html/rfc6455#section-3)
* [websocket extensions](http://tools.ietf.org/html/rfc6455#section-9)
* [websocket subprotocols](http://tools.ietf.org/html/rfc6455#section-1.9)
* [status codes](http://tools.ietf.org/html/rfc6455#section-7.4) 
* [cookies and/or authentication-related header fields](http://tools.ietf.org/html/rfc6455#page-19)
* [continuation frame](http://tools.ietf.org/html/rfc6455#section-11.8) (all payload data must be encapsulated into one websocket frame)
* big frames, which payload size bigger than 0xFFFF
 
