#!/bin/bash

cd `dirname $0`

HTTEST=../httpd/support/httest

${HTTEST} $@
RC=$?
if [ $RC -ne 0 ]; then
    exit $RC
fi

exit 0
