rm implementations -rf
rm PIN -rf
mkdir implementations
git clone git://git.openssl.org/openssl.git implementations/openssl
cp implementations/openssl implementations/openssl_afl -r
wget -qO- http://software.intel.com/sites/landingpage/pintool/downloads/pin-3.0-76991-gcc-linux.tar.gz | tar xvz
mv pin-3.0-76991-gcc-linux PIN
cd PinScripts
make -f makefile PIN_ROOT=../PIN/
cd ..
cd AFL
make clean
make
cd ..
cd implementations/openssl
./config -fsanitize=address --prefix=`pwd`/openssl/ --openssldir=`pwd`/openssl/ no-shared -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign
make -j10
make install
cd ..
cd openssl_afl
make clean
export AFL_USE_ASAN=1;
export AFL_HARDEN=1; 
CC=../../AFL/afl-gcc ./config --prefix=`pwd`/openssl/ --openssldir=`pwd`/openssl/ no-shared -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign
make
make install
