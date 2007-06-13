#!/bin/sh -e
touch aclocal.m4
touch INSTALL NEWS AUTHORS ChangeLog COPYING
aclocal
autoconf
automake -a
automake