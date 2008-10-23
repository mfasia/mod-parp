#!/bin/bash

ulimit -c unlimited


if [ "$1" = "restart" ]; then
    ../httpd/httpd -d Server -k stop
    sleep 1
    ../httpd/httpd -d Server -k start
else
    if [ -n "$2" -a "$1" = "start" ]; then
        shift
        ../httpd/httpd -d Server $@
    else
	../httpd/httpd -d Server -k $1
    fi
fi
if [ "$1" = "start" ]; then
    sleep 1
    ps -p `cat Server/logs/pid` 1>/dev/null 2>/dev/null
    echo $?
fi
