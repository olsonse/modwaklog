ALL=	mod_afs.so

APXS=	apxs
CC=	gcc

INC=	-I/usr/local/krb5/include -I/usr/local/openafs/include \
	-I/usr/local/apache/include
LIB=    -L/usr/local/krb5/lib \
	-lkrb4 -lkrb5 -ldes425 -lk5crypto -lcom_err -lsocket -lnsl \
	-L/usr/local/openafs/lib/afs -lsys \
	-L/usr/local/openafs/lib -lrx -llwp
CFLAGS=	${DEF} ${INC} -DEAPI
OBJ=	mod_afs.o lifetime.o version.o

all:	${ALL}

version.o : version.c
	date +%Y%m%d > VERSION
	${CC} ${CFLAGS} \
	    -DVERSION=\"`cat VERSION`\" \
	    -c version.c

mod_afs.so:  ${OBJ}
	${APXS} -c ${LIB} ${OBJ}

clean:
	rm -f *.o *.so a.out core
	rm -f ${ALL}
