OBJS = main.o init.o net.o time_math.o lexer.o parser.o
LIBS = -lpthread -lnsl -lsocket
CC = gcc
CFLAGS = -g -D_POSIX_PTHREAD_SEMANTICS
svrrpd: $(OBJS)
	gcc -o svrrpd $(OBJS) $(LIBS) 
main.o net.o time_math.o init.o lexer.o parser.o: vrrpd.h sysmac.h
lex.yy.c: lexer.l
y.tab.c: parser.y

clean:
	rm $(OBJS) svrrpd 
