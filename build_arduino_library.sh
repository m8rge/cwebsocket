#!/bin/bash

mkdir -p arduino_library/websocket/examples/echo
cp lib/* arduino_library/websocket
cp arduino_server/arduino_server.ino arduino_library/websocket/examples/echo/echo.ino
echo "arduino library builded successfully"