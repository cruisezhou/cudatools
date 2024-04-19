

objs=${patsubst %.c,%.o,${wildcard *.c}}
target=fatbinary
all:$(target)

$(target):${objs}
	${CC} $^ -o $@

.PHONY:clean
clean:
	-rm -rf ${objs} ${target}
	