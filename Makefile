# File: Makefile
# Written by: Christopher Jordan
# Adopted from work by: Chris Wailes <chris.wailes@gmail.com>
# Adapted from work by: Andy Sayler <Github User: asayler>
# Project: CSCI 3753 Programming Assignment 4
# Creation Date: 2010/04/06
# Modififed Date: 2014/04/23
# Description:
#	This is the Makefile for PA4.


CC           = gcc

CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

PA4-ENCFS = pa4-encfs

.PHONY: all pa4-encfs clean

all: pa4-encfs 

pa4-encfs: pa4-encfs.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

pa4-encfs.o: pa4-encfs.c 
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f *.o
	rm -f *~
	rm -f handout/*~
	rm -f handout/*.log
	rm -f handout/*.aux
	rm -f handout/*.out



