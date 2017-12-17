#!/bin/bash

make config T=x86_64-native-linuxapp-gcc
make T=x86_64-native-linuxapp-gcc -j 8
make install T=x86_64-native-linuxapp-gcc -j 8
