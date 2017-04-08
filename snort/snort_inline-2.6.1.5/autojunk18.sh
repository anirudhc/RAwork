#!/bin/sh
# the list of commands that need to run before we do a compile
# This one works on Debian Sarge and Ubuntu Dapper. Using the
# default autojunk.sh caused problems with the dynamic plugins. VJ.
libtoolize --automake --copy
aclocal-1.8 -I m4
autoheader
automake-1.8 --add-missing --copy
autoconf

