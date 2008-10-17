#!/bin/bash

ulimit -c unlimited
../httpd/httpd -d Server -k $1 

if [ "$1" = "start" ]; then
    sleep 1
    ps -p `cat Server/logs/pid` 1>/dev/null 2>/dev/null
    echo $?
fi
