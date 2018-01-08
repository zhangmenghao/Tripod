#!/bin/bash
make; sudo ./build/gateway -l 0-2 -n 3 -b 82:00.1 --proc-type auto --socket-mem 1024,1024 --file-prefix gw -- -p 0x1

