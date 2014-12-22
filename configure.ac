# configure.ac -- autoconf file
#
#       ╔════════════════════════════════╗
#       ║ This file uses UTF-8 encoding. ║
#       ╚════════════════════════════════╝
#
# Copyright © 2011, Gregory ROMÉ
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Gregory ROMÉ nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY GREGORY ROMÉ ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL GREGORY ROMÉ LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# ==============================================================================
# Autoconf Layout
#
# 1.  Autoconf requirements
# 2.  AC_INIT(package, version, bug-report-address)
# 3.  information on the package
# 4.  checks for programs
# 5.  checks for libraries
# 6.  checks for header files
# 7.  checks for types
# 8.  checks for structures
# 9.  checks for compiler characteristics
# 10. checks for library functions
# 11. checks for system services
# 12. AC_CONFIG_FILES([file...])
# 13. AC_OUTPUT

# ==============================================================================
# 1. Autoconf requirements
AC_PREREQ(2.59)

# ==============================================================================
# 2. AC_INIT(package, version, bug-report-address)
define([VERSION_NUMBER], [0.0.1]) # For sharing the version number
AC_INIT([iexdissectors], [VERSION_NUMBER], [roc@iextrading.com])


# ==============================================================================
# 3. information on the package
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_SYSTEM
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([foreign dist-bzip2])
AM_SILENT_RULES([yes])

if test "x$AM_DEFAULT_VERBOSITY" = "x0"
then
	AM_MAKEFLAGS="$AM_MAKEFLAGS --no-print-directory"
	AC_SUBST(AM_MAKEFLAGS)
fi

# ------------------------------------------------------------------------------
# Options

AM_MAINTAINER_MODE([enable])

AC_ARG_WITH([dissector-dir],
        [AS_HELP_STRING([--with-dissector-dir=<plugindir>],
                [Set the installation directory for the wireshark dissector])],
        [dissectordir=$withval], [dissectordir=${libdir}/wireshark/plugins])

AC_SUBST([DISSECTOR_DIR], [$dissectordir])


# ==============================================================================
# 4. checks for programs


# ==============================================================================
# 5.  checks for libraries

PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([WIRESHARK], [wireshark], [], [
	WIRESHARK_CFLAGS="-DWS_VAR_IMPORT=extern -DWS_MSVC_NORETURN= -I/usr/include/wireshark -I/usr/include/wireshark/epan"
	WIRESHARK_LIBS="-Wl,--export-dynamic -lwireshark -lwiretap"
])

# ==============================================================================
# 6.  checks for header files

# Manual check required because Ubuntu's libwireshark-dev pkgconfig is b0rked
AC_CHECK_HEADERS_ONCE([stdarg.h])

# ==============================================================================
# 7.  checks for types
# ==============================================================================
# 8.  checks for structures
# ==============================================================================
# 9.  checks for compiler characteristics

AC_PROG_CC
AC_PROG_CC_STDC

# ==============================================================================
# 10. checks for library functions

#AC_SEARCH_LIBS([clock_gettime], [rt])
#AC_SEARCH_LIBS([roundl], [m])

# Adjust CFLAGS here so as not to break tests elsewhere
# Hardcode WIRESHARK_CFLAGS wackiness because Ubuntu

CPPFLAGS="-Wall -Werror -Wextra -Wpadded -Wstrict-aliasing=2 -DWS_VAR_IMPORT=extern -DWS_MSVC_NORETURN="
CFLAGS="-g -O3 -fno-guess-branch-probability -march=native"

AM_PROG_LIBTOOL
LT_INIT([shared static pic-only])

# ==============================================================================
# 11. checks for system services
# ==============================================================================
# 12. AC_CONFIG_FILES([file...])

AC_CONFIG_FILES(Makefile
		src/Makefile
		src/packet-iexdissectors.h)

# ==============================================================================
AC_OUTPUT
