# Process this file with autoconf to produce a configure script.
AC_INIT([dyner], [8.0])
AC_CONFIG_SRCDIR([src/dyner.C])
AC_PREFIX_DEFAULT([.])
AC_CONFIG_AUX_DIR([./autodyninst])

# Generate host string.
AC_CANONICAL_HOST()

# Build all configure tests with C++ compiler.
AC_LANG([C++])

# sha1.C requres these system files and endianess to be tested.
AC_CHECK_HEADERS([inttypes.h], [], [], [// Do not use default includes])
AC_CHECK_HEADERS([stdint.h], [], [], [// Do not use default includes])
AC_C_BIGENDIAN()

AC_SEARCH_LIBS(dlopen, dl)

AC_ARG_WITH(dyninst,
            [AS_HELP_STRING([--with-dyninst],[Base directory to look for dyninst headers and libraries])],
            [DYNINST_LIB_DIR="${withval}/lib"
             DYNINST_INC_DIR="${withval}/include"],)

AC_ARG_WITH(dyninst-lib,
            [AS_HELP_STRING([--with-dyninst-lib],[Directory to look for dyninst libraries])],
            [DYNINST_LIB_DIR="${withval}"],)

AC_ARG_WITH(dyninst-include,
            [AS_HELP_STRING([--with-dyninst-include],[Directory to look for dyninst headers])],
            [DYNINST_INC_DIR="${withval}"],)
if test "x$DYNINST_INC_DIR" != "x" ; then
   CPPFLAGS="-I${DYNINST_INC_DIR} ${CPPFLAGS}"
fi
if test "x$DYNINST_LIB_DIR" != "x" ; then
   LDFLAGS="-L${DYNINST_LIB_DIR} ${LDFLAGS}"
fi
# Search for Dyninst in all the right places.

AC_CHECK_HEADER([BPatch.h], [],
		[AC_MSG_ERROR([Cannot find DyninstAPI library include files.])],
		[// Do not use default includes])

# Check if Dyninst is version 5.0+
AC_CHECK_HEADERS([BPatch_process.h],
		 [AC_SUBST([DYNINST_VER], [5])],
		 [AC_SUBST([DYNINST_VER], [4])],
		 [// Do not use default includes])


AC_ARG_WITH(libdwarf,
            [AS_HELP_STRING([--with-libdwarf],[LIBDWARF directory (must contain ./lib and ./include)])],
            [LIBDWARF_INC_DIR="${withval}/include";
            LIBDWARF_LIB_DIR="${withval}/lib";],)
AC_ARG_WITH(libdwarf-incdir,
            [AS_HELP_STRING([--with-libdwarf-incdir],[LIBDWARF include directory])],
            [LIBDWARF_INC_DIR="${withval}";],)
AC_ARG_WITH(libdwarf-libdir,
            [AS_HELP_STRING([--with-libdwarf-libdir],[LIBDWARF library directory])],
            [LIBDWARF_LIB_DIR="${withval}";],)
if test "x$LIBDWARF_INC_DIR" != "x" ; then
   CPPFLAGS="-I${LIBDWARF_INC_DIR} ${CPPFLAGS}"
fi
if test "x$LIBDWARF_LIB_DIR" != "x" ; then
   LDFLAGS="-L${LIBDWARF_LIB_DIR} ${LDFLAGS}"
   AC_CHECK_LIB([dwarf], [dwarf_next_cu_header_c], [AC_MSG_NOTICE(DWARF library directory: $LIBDWARF_LIB_DIR)],
       [AC_ERROR(couldn't find sufficiently recent libdwarf (> 2011-12) with dwarf_next_cu_header_c)], [-lelf])
fi


AC_ARG_WITH(libelf,
            [AS_HELP_STRING([--with-libelf],[LIBELF directory (must contain ./lib and ./include)])],
            [LIBELF_INC_DIR="${withval}/include";
            LIBELF_LIB_DIR="${withval}/lib";],)
AC_ARG_WITH(libelf-incdir,
  	   [AS_HELP_STRING([--with-libelf-incdir],[LIBELF include directory])],
	   [LIBELF_INC_DIR="${withval}";],)
AC_ARG_WITH(libelf-libdir,
           [AS_HELP_STRING([--with-libelf-libdir],[LIBELF library directory])],
           [LIBELF_LIB_DIR="${withval}";],)
if test "x$LIBELF_INC_DIR" != "x" ; then
   CPPFLAGS="-I${LIBELF_INC_DIR} ${CPPFLAGS}"
fi
if test "x$LIBELF_LIB_DIR" != "x" ; then
   LDFLAGS="-L${LIBELF_LIB_DIR} ${LDFLAGS}"
fi

AC_ARG_WITH(liberty-lib,
            [AS_HELP_STRING([--with-liberty-libdir],[libiberty library directory])],
            [LIBIBERTY_LIB_DIR="${withval}"],)
if test "x$LIBIBERTY_LIB_DIR" != "x" ; then
   LDFLAGS="-L${LIBIBERTY_LIB_DIR} ${LDFLAGS}"
   AC_CHECK_LIB([iberty], [cplus_demangle], [HAVE_LIBIBERTY="true";],[HAVE_LIBIBERTY="false"])
fi


AC_SUBST([LDFLAGS], ["${LDFLAGS}"])
AC_SUBST([CPPFLAGS], ["${CPPFLAGS}"])


AC_ARG_WITH(tcl83,
            [AS_HELP_STRING([--with-tcl83],[Use Tcl/Tk 8.3])],
            [TCL_VERSION="8.3"; USE_TCL83="${withval}";],
            [TCL_VERSION="8.4"; USE_TCL83="false";])
AC_ARG_WITH(tcltk,
            [AS_HELP_STRING([--with-tcltk],[TCL/TK directory (must contain ./lib and ./include)])],
            [TCLTK_INC_DIR="${withval}/include";
             TCLTK_LIB_DIR="${withval}/lib";],)
AC_ARG_WITH(tcltk-incdir,
            [AS_HELP_STRING([--with-tcltk-incdir],[TCL/TK include directory])],
            [TCLTK_INC_DIR="${withval}";],)
AC_ARG_WITH(tcltk-libdir,
            [AS_HELP_STRING([--with-tcltk-libdir],[TCL/TK library directory])],
            [TCLTK_LIB_DIR="${withval}";],)
AC_SUBST(USE_TCL83)
AC_SUBST([LDFLAGS], ["-L${TCLTK_LIB_DIR} ${LDFLAGS}"])
AC_SUBST([CPPFLAGS], ["-I${TCLTK_INC_DIR} ${CPPFLAGS}"])
AC_SUBST(TCLTK_LIB_DIR)
AC_CHECK_LIB(tcl${TCL_VERSION}, Tcl_Init)
AC_CHECK_LIB(tk${TCL_VERSION}, Tk_Init)


# Find appropriate install program
AC_PROG_INSTALL()

AC_CONFIG_FILES([Makefile])
AC_OUTPUT()
