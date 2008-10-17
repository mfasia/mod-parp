#!/bin/sh

./bootstrap.sh

ERRORS=0
WARNINGS=0

./ctl.sh start

./htt.sh -s scripts/main_func.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED main_func.htt"
fi

./ctl.sh stop

if [ $WARNINGS -ne 0 ]; then
    echo "ERROR: got $WARNINGS warnings"
fi

if [ $ERRORS -ne 0 ]; then
    echo "ERROR: end with $ERRORS errors"
    exit 1
fi

CFS=`find . -name "*core*"`
if [ "$CFS" != "" ]; then
    echo "ERROR: found core file"
    exit 1
fi

echo "normal end"
exit 0