CC ?= cc
STRIP ?= strip

all:
	${CC} -Wall keytable.c -o keytable
	${STRIP} keytable

clean:
	${RM} keytable

install:
