#!/bin/bash

. ./include.sh

MODULE=parp

cd httpd/modules
if [ ! -d $MODULE ]; then
  mkdir $MODULE
fi
cd $MODULE

for E in `find ../../../httpd_src/modules/$MODULE -type f | grep -v CVS `; do
  rm -f `basename $E`
  ln -s $E `basename $E`
done

cd ../../support
for E in `find ../../httpd_src/support -type f | grep -v CVS `; do
  rm -f `basename $E`
  ln -s $E `basename $E`
done
