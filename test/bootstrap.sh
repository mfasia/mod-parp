#!/bin/bash
SERVER_ROOT=`pwd`/Server

sed < Server/conf/httpd.conf.tmpl > Server/conf/httpd.conf \
  -e "s;##SERVER_ROOT##;$SERVER_ROOT;g"

