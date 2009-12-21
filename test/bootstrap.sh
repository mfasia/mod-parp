#!/bin/bash
SERVER_ROOT=`pwd`/Server

QS_UID=`id`
QS_UID_STR=`expr "$QS_UID" : 'uid=[0-9]*.\([a-z,A-Z,0-9,_]*\)'`

sed < Server/conf/httpd.conf.tmpl > Server/conf/httpd.conf \
  -e "s;##SERVER_ROOT##;$SERVER_ROOT;g" \
  -e "s;##USER##;$QS_UID_STR;g"

