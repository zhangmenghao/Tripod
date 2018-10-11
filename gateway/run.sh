#!/bin/bash
sudo ./build/gateway -l 0-2 -n 3 -b 81:00.0 --proc-type auto --socket-mem 1024,1024 --file-prefix gw1 -- -p 0x1

