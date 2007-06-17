all: mod_waklog.so

APXS = @APXS@
INCLUDES = -I@KRB5_INC@ -I@AFS_INC@ -I@APACHE_INC@
LIB = -L@KRB5_LIBS@ -L@AFS_LIBS@ -L@APACHE_LIBS@ -lkrb5 -lk5crypto  \
       -lprot -lauth -lresolv -lubik -lrxkad -lsys -lrx -llwp -ldes \
       -lcom_err -lafsutil

APXSCC = `${APXS} -q CC` \
         @WAKLOG_DEBUG@ \
         ${INCLUDES} \
         -DEAPI \
         -g \
         `${APXS} -q CFLAGS`

VERSION: mod_waklog.c
	date '+SVN_%Y%m%d' > VERSION

version.o: version.c mod_waklog.c VERSION
	${APXSCC} \
	    -DVERSION=\"`cat VERSION`\" \
	    -c version.c

%.o: %.c
	${APXSCC} -c $< -o $@
mod_waklog.so: mod_waklog.o lifetime.o version.o
	${APXS} -c ${LIB} mod_waklog.o lifetime.o version.o

clean:
	rm -f *.o *.so
	rm -f mod_waklog.so
