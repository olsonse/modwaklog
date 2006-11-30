ALL=	mod_waklog.so

APXS=	/usr/sbin/apxs
CC=	gcc

INC=    -I/usr/local/mit-k5/include \
        -I/usr/include	\
	-I/usr/include/apr-0

LIB=    -L/usr/local/mit-k5/lib \
	-lkrb5 -lk5crypto -lcom_err \
	-L/usr/lib/afs -lsys -lrx -llwp -lauth -lafsutil -lresolv 

CFLAGS=	${DEF} ${INC} -DEAPI -g
OBJ=	mod_waklog.o lifetime.o version.o

all:	${ALL}

version.o : version.c
	date +%Y%m%d > VERSION
	${CC} ${CFLAGS} \
	    -DVERSION=\"`cat VERSION`\" \
	    -c version.c

mod_waklog.so:  ${OBJ}
	${APXS} -c ${LIB} ${OBJ}
	mv  .libs/${ALL} .

clean:
	rm -f *.o *.so a.out core 
	rm -f ${ALL}
	rm -rf .libs
