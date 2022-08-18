INC = -I/usr/include/libusb-1.0/ 
CFLAGS=$(OPT) -Wall -W -Wno-parentheses -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter -fPIC -pthread
CC=gcc

all:default

default:libusb-test-app-async

libusb-test-app-async:
	$(CC) -g -o libusb-test-app-async -D_REENTRANT libusb-test-app-async.c $(CFLAGS) $(INC) `pkg-config --libs --cflags libusb-1.0` 

libusb-test-app-sync:
	$(CC) -g -o libusb-test-app-sync -D_REENTRANT libusb-test-app-sync.c $(CFLAGS) $(INC) `pkg-config --libs --cflags libusb-1.0`
