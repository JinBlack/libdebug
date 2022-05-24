.PHONY: all test read_test write_test read_test_thread
FLAG = -O2 -g
FLAG_THREAD = -g -lpthread

all: test read_test write_test read_test_thread

test: test.c
	gcc $(FLAG) -o $@ $<

read_test: read_test.c
	gcc $(FLAG) -o $@ $<

write_test: write_test.c
	gcc $(FLAG) -o $@ $<

read_test_thread: read_test_thread.c
	gcc $(FLAG_THREAD) -o $@ $<

