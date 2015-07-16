#!/bin/sh -e
aclocal
autoconf
automake --add-missing
automake
