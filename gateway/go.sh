#!/bin/bash
make; sudo ./build/gateway -l 0-3 -n 3 -b 82:00.1 --proc-type auto --socket-mem 2048,2048 --file-prefix gw -- -p 0x1

