rm PIN -rf
mkdir implementations
wget -qO- http://software.intel.com/sites/landingpage/pintool/downloads/pin-3.0-76991-gcc-linux.tar.gz | tar xvz
mv pin-3.0-76991-gcc-linux PIN
cd PinScripts
make -f makefile PIN_ROOT=../PIN/
cd ..
cd AFL
make clean
make
./afl-gcc test.c -o test
