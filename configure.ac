AC_INIT([mod_waklog], [1.1.0])
AC_CONFIG_SRCDIR([mod_waklog.c])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_WITH([afs-libs],
            [AC_HELP_STRING([--with-afs-libs],[path to afs libraries])],
            [AFS_LIBS=$withval],
            [AFS_LIBS=/usr/lib/afs])
AC_SUBST(AFS_LIBS)

AC_ARG_WITH([afs-headers],
            [AC_HELP_STRING([--with-afs-headers],[path to afs headers])],
            [AFS_INC=$withval],
            [AFS_INC=/usr/include/afs])
AC_SUBST(AFS_INC)

AC_ARG_WITH([krb5-libs],
            [AC_HELP_STRING([--with-krb5-libs],[path to krb5 libraries])],
            [KRB5_LIBS=$withval],
            [KRB5_LIBS=/usr/lib/])
AC_SUBST(KRB5_LIBS)

AC_ARG_WITH([krb5-headers],
            [AC_HELP_STRING([--with-krb5-headers],[path to krb5 headers])],
            [KRB5_INC=$withval],
            [KRB5_INC=/usr/include/])
AC_SUBST(KRB5_INC)

AC_ARG_WITH([apache-libs],
            [AC_HELP_STRING([--with-apache-libs],[path to apache libraries])],
            [APACHE_LIBS=$withval],
            [APACHE_LIBS=/usr/lib/])
AC_SUBST(APACHE_LIBS)

AC_ARG_WITH([apxs],
            [AC_HELP_STRING([--with-apxs],[path to apxs])],
            [APXS=$withval],
            [APXS=apxs])
AC_SUBST(APXS)

AC_ARG_ENABLE(debug,
 [  --enable-debug uncomment this if you want an insane amount of debug information
 ],
 [ WAKLOG_DEBUG=-DWAKLOG_DEBUG
 ])
AC_SUBST(WAKLOG_DEBUG)

AC_OUTPUT(Makefile)
