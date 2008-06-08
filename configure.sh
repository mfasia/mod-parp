#!/bin/bash

. ./include.sh

cd $HTTPD
./buildconf
./configure --prefix=$HOME/local \
            --enable-so \
            --enable-static-support \
            --enable-param-parser=static \
	    --enable-ssl
