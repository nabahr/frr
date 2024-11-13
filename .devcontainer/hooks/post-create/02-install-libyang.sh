#!/bin/bash

cd /tmp
git clone https://github.com/CESNET/libyang.git
cd libyang
git checkout v2.1.128
mkdir build
cd build
cmake --install-prefix /usr -D CMAKE_BUILD_TYPE:String="Release" ..
make
sudo make install
