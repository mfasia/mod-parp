#!/bin/bash

. ./include.sh

MODULE=param_parser

cd httpd/modules
mkdir $MODULE
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
