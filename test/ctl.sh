#!/bin/bash

ulimit -c unlimited

APA24=""
if [ `../httpd/httpd -v | grep -c "Apache/2.4"` -eq 1 ]; then
  APA24="-D apache24"
fi

if [ "$1" = "restart" ]; then
    ../httpd/httpd -d Server -k stop
    sleep 1
    ../httpd/httpd -d Server $APA24 -k start
else
    if [ -n "$2" -a "$1" = "start" ]; then
        shift
        ../httpd/httpd -d Server $APA24 $@
    else
	../httpd/httpd -d Server $APA24 -k $1
    fi
fi
if [ "$1" = "start" ]; then
    sleep 1
    ps -p `cat Server/logs/pid` 1>/dev/null 2>/dev/null
    echo $?
fi
