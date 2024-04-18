all: wireview

wireview: wireview.c
	gcc -o wireview wireview.c -lpcap

clean:
	rm -f wireview