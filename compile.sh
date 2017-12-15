#! /bin/bash

echo "Compiling and installing dpdk in $RTE_SDK"
make config T=$RTE_TARGET
make T=$RTE_TARGET -j 8
make install T=$RTE_TARGET -j 8
