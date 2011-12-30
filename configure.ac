AC_INIT(nfacct, 1.0.0-beta, pablo@netfilter.org)

AC_CANONICAL_HOST

AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AM_PROG_LEX
AC_PROG_YACC

case "$host" in
*-*-linux*) ;;
*) AC_MSG_ERROR([Linux only, dude!]);;
esac

PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.0])
PKG_CHECK_MODULES([LIBNETFILTER_ACCT], [libnetfilter_acct >= 1.0.0])

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile include/linux/Makefile include/linux/netfilter/Makefile])
AC_OUTPUT
