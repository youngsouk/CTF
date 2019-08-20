#!/bin/sh
cd /home/ytf
wget https://github.com/VirusTotal/yara/archive/v3.10.0.tar.gz
tar -zxf v3.10.0.tar.gz
cd yara-3.10.0
patch -s -p1 < ../patchfile
./bootstrap.sh
./configure CFLAGS='-g -O2 -no-pie -Wl,-z,relro'
make
make install
ln -s /usr/local/lib/libyara.so.3.9.0 /lib/libyara.so.3
