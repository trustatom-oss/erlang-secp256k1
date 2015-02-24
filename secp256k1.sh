#! /bin/sh

[ -f secp256k1/.libs/libsecp256k1.a ] && exit 0

git clone https://github.com/bitcoin/secp256k1
cd secp256k1
git checkout 0bada0e2a9f8fc3ba0096005d3f0498b70a5c885
./autogen.sh
./configure
make
./tests
