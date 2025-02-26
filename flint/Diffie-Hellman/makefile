CFLAGS = -v -c -ggdb -Wall -ansi -I../src -o $@

STDCPP=stdc++ -lm
EXECUTABLE = -ggdb -o d-h_test

d-h_test: main.o flintpp.o flint.o random.o entropy.o aes.o ripemd.o sha1.o randompp.o
	gcc $(EXECUTABLE) main.o random.o entropy.o aes.o ripemd.o sha1.o randompp.o flintpp.o flint.o -l$(STDCPP)

main.o: main.cpp
	gcc $(CFLAGS) main.cpp

flintpp.o: ../src/flintpp.cpp
	gcc $(CFLAGS) ../src/flintpp.cpp

flint.o: ../src/flint.c
	gcc $(CFLAGS) ../src/flint.c

ripemd.o: ../src/ripemd.c
	gcc $(CFLAGS) ../src/ripemd.c

randompp.o: ../src/randompp.cpp
	gcc $(CFLAGS) ../src/randompp.cpp

random.o: ../src/random.c
	gcc $(CFLAGS) ../src/random.c

aes.o: ../src/aes.c
	gcc $(CFLAGS) ../src/aes.c

sha1.o: ../src/sha1.c
	gcc $(CFLAGS) ../src/sha1.c

entropy.o: ../src/entropy.c
	gcc $(CFLAGS) ../src/entropy.c

