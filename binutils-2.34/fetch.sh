#!/bin/sh
MIRROR=mirrors.edge.kernel.org
#MIRROR=archive.debian.org
pwd | grep opcode-0002/binutils-2.34 || pwd | grep opcode/binutils-2.34 || exit 0
wget https://$MIRROR/debian/pool/main/b/binutils/binutils_2.34.orig.tar.xz
ln -sf . binutils-2.34
tar --keep-directory-symlink -Jxpvf binutils_2.34.orig.tar.xz
wget https://$MIRROR/debian/pool/main/b/binutils/binutils_2.34-2.debian.tar.xz
tar Jxpvf binutils_2.34-2.debian.tar.xz
ln -sf . a
ln -sf . b
for p in $(cat series.txt); do cat debian/patches/$p; done | patch -p0
rm -f a b
echo "now do: ./configure --prefix=/usr/i686-elf --target=i686-elf; nice make -j4"
