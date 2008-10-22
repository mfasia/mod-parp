#!/bin/sh
# -*-mode: ksh; ksh-indent: 2; -*-
#
# $Header$
#
# Script to build file release
#
# ./doc
# contains the index.html/readme about mod_parp
# ./apache
# contains the source code
#
# See http://parp.sourceforge.net/ for further details about mod_parp.
#

TOP=`pwd`
VERSION=`grep "char g_revision" httpd_src/modules/parp/mod_parp.c | awk '{print $6}' | awk -F'"' '{print $2}'`

TAGV=`echo $VERSION | awk -F'.' '{print "REL_" $1 "_" $2}'`
echo "check release tag $TAGV ..."
#if [ "`cvs -q diff -r $TAGV 2>&1`" = "" ]; then
#  echo ok
#else
#  echo "FAILED"
#  exit 1
#fi

rm -rf mod_parp-${VERSION}*
mkdir -p mod_parp-${VERSION}/doc
mkdir -p mod_parp-${VERSION}/apache2

echo "install documentation"
#cp doc/README.TXT mod_parp-${VERSION}
#cp doc/LICENSE.txt mod_parp-${VERSION}/doc
#cp doc/CHANGES.txt mod_parp-${VERSION}/doc
sed <doc/index.html >mod_parp-${VERSION}/doc/index.html -e "s/4.15/${VERSION}/g"

echo "install source"
cp httpd_src/modules/parp/mod_parp.c mod_parp-${VERSION}/apache2

echo "package: mod_parp-${VERSION}-src.tar.gz"
tar cf mod_parp-${VERSION}-src.tar --owner root --group bin mod_parp-${VERSION}
gzip mod_parp-${VERSION}-src.tar
rm -r mod_parp-${VERSION}

echo "END"
