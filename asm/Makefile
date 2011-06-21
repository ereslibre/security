all: helloworld

helloworld: helloworld.asm
	nasm -f elf64 helloworld.asm
	ld helloworld.o -o helloworld

clean:
	rm helloworld helloworld.o
