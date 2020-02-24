all:
	gcc -o 0001 0001.c -Iinclude i386-dis.c -lopcodes
	gcc -o 0002 0002.c -Iinclude i386-dis.c -lopcodes
#all:; gcc -o 0001 0001.c -L/usr/i686-elf/lib -I/usr/i686-elf/include -Ibinutils-2.34/opcodes -lopcodes #fail
#all:; gcc -o 0001 0001.c -L/usr/i686-elf/lib -I/usr/i686-elf/include -Iinclude i386-dis.c -lopcodes
# -liberty -ldl -lz
#root@localhost:/home/mdasoh/app/opcode/binutils-2.34/libiberty# grep sch_istable *.c
#safe-ctype.c:const unsigned short _sch_istable[256] =
#echo "void _start(){ for(;;); }" > 0003.c
#i686-elf-gcc -o 0003.o 0003.c -ffreestanding -nostdlib -fno-asynchronous-unwind-tables
0003: 0001 0002
	echo "        .global         _start" > 0003.s
	echo "_start:" >> 0003.s
	./0001 >> 0003.s
	/usr/i686-elf/bin/i686-elf-as -march=i386 -mmnemonic=intel -msyntax=intel -mnaked-reg -o 0003.o 0003.s
	/usr/i686-elf/bin/i686-elf-ld --oformat=binary -o 0003 0003.o
	cat 0003 | xxd
	echo "        .global         _start" > 0004.s
	echo "_start:" >> 0004.s
	./0002 0004 >> 0004.s
	/usr/i686-elf/bin/i686-elf-as -march=i386 -mmnemonic=intel -msyntax=intel -mnaked-reg -o 0004.o 0004.s
	/usr/i686-elf/bin/i686-elf-ld --oformat=binary -o 0004 0004.o
	cat 0004 | xxd
	rm 0003
	cat 0004.s

run:
	as -march=i386 -mmnemonic=intel -msyntax=intel -mnaked-reg -o 0005.o 0004.s
	ld -o 0005 0005.o
	./0005

edit:
	beav 0004.orig
	cp -a 0004.orig 0004
