#!/bin/bash

. ./include.sh

tar xzvSpf ./3thrdparty/$HTTPD.tar.gz
ln -s $HTTPD httpd
