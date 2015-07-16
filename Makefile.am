all: mod_waklog.so

APXS = @APXS@
AM_CPPFLAGS = -I@KRB5_INC@ -I@AFS_INC@
LIB = -L@AFS_LIBS@ -L@KRB5_LIBS@
LIB += -lkrb5 -lk5crypto -lafsauthent -lafsrpc -lkopenafs

APXSCC = `${APXS} -q CC` \
         @WAKLOG_DEBUG@ \
         -DVERSION=\"@VERSION@\" \
         ${AM_CPPFLAGS} \
         -DEAPI -fPIC \
         -g \
         `${APXS} -q CFLAGS` \
         -I`${APXS} -q INCLUDEDIR` \
         -I`${APXS} -q APR_INCLUDEDIR`

.c.o:
	${APXSCC} -c $< -o $@

mod_waklog.so: mod_waklog.o lifetime.o
	${APXS} -c ${LIB} mod_waklog.o lifetime.o

clean:
	rm -f *.o *.so
