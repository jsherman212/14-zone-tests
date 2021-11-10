SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CC = $(shell xcrun --sdk $(SDK) --find clang)
CFLAGS = -g -arch arm64 -isysroot $(SDK) -Wno-deprecated-declarations
CFLAGS += -fno-stack-protector -D_FORTIFY_SOURCE=0

all : ztests

kernel_hooks.o : kernel_hooks.c xnuspy_ctl.h
	$(CC) $(CFLAGS) kernel_hooks.c -c

ztests : kernel_hooks.o main.c 
	$(CC) $(CFLAGS) kernel_hooks.o main.c -o ztests
	ldid -Sent.xml ./ztests
	rsync -sz -e 'ssh -p 2222' ztests root@localhost:/var/root
