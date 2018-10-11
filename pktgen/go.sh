#!/bin/bash
make; sudo ./build/pktgen -l 0-2 -n 3 -b 04:00.0 --proc-type auto --socket-mem 4096 --file-prefix bf -- -p 0x1

