CC = g++
CFLAGS = -std=c++11 -Wall -pedantic -g3 -O3

all: main

.PHONY: main
main:
	$(CC) $(CFLAGS) ./app/*.cpp ./src/*.cpp -I./inc -o main

clean:
	rm main