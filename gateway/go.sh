#!/bin/bash
make; sudo ./build/gateway -l 1,3,5,7,9,11,13,15,17,19,21,23 -n 4  -b 04:00.0 --proc-type auto --socket-mem 8192 --file-prefix gw -- -p 0x1
