all: arm x86

arm: rootify.c
	./agcc -o rootify-arm rootify.c

x86: rootify.c
	gcc -o rootify-x86 rootify.c

clean:
	rm rootify-*
