#!/bin/bash
sudo ./build/gateway -l 3-5 -n 3 -b 81:00.1 --proc-type auto --socket-mem 1024,1024 --file-prefix gw2 -- -p 0x1

