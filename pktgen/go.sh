#!/bin/bash
make; sudo ./build/pktgen -l 5 -n 3 -b 81:00.0 --proc-type auto --socket-mem 512,512 --file-prefix bf -- -p 0x1

