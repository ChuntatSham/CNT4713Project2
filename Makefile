CC = gcc

mydns:
	$(CC) mydns.c -o mydns -Wall -pedantic -std=gnu99
exec:
	./mydns