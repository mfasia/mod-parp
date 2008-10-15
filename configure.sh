#!/bin/bash

. ./include.sh

cd $HTTPD
./buildconf
CFLAGS="-g" ./configure \
  --prefix=$HOME/local \
  --enable-so \
  --enable-static-support \
  --enable-param-parser=static \
  --enable-parp=static \
  --enable-ssl
