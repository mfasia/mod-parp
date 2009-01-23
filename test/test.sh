#!/bin/sh

./bootstrap.sh

ERRORS=0
WARNINGS=0

./ctl.sh start
#ps -Ao vsz,comm,pid,ppid | grep `cat Server/logs/pid` | sort -n | tail -1 | awk '{print $1 " " $3}'

./htt.sh -s scripts/main_func.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED main_func.htt"
fi
./htt.sh -s scripts/loop.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED loop.htt"
fi
./htt.sh -s scripts/file.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED file.htt"
fi
./htt.sh -s scripts/big.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED big.htt"
fi
./htt.sh -s scripts/textplain.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED textplain.htt"
fi
./htt.sh -s scripts/texthtml.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED texthtml.htt"
fi
./htt.sh -s scripts/body.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED body.htt"
fi
./htt.sh -s scripts/modify.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED body.htt"
fi

#for E in `seq 7`; do
#ps -Ao vsz,comm,pid,ppid | grep `cat Server/logs/pid` | sort -n | tail -1 | awk '{print $1 " " $3}'
#./htt.sh -s scripts/big.htt
#if [ $? -ne 0 ]; then
#    ERRORS=`expr $ERRORS + 1`
#    echo "FAILED big.htt"
#fi
#done
#
#ps -Ao vsz,comm,pid,ppid | grep `cat Server/logs/pid` | sort -n | tail -1 | awk '{print $1 " " $3}'
./ctl.sh stop
sleep 1
./ctl.sh start -D noerror
sleep 1
./htt.sh -s scripts/error.htt
if [ $? -ne 0 ]; then
    ERRORS=`expr $ERRORS + 1`
    echo "FAILED error.htt"
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
