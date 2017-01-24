rm PIN -rf
rm AFL -rf
mkdir implementations
mkdir PIN
mkdir AFL
wget -qO- http://software.intel.com/sites/landingpage/pintool/downloads/pin-3.0-76991-gcc-linux.tar.gz | tar xvz -C PIN/ --strip-components=1
cd PinScripts
make -f makefile PIN_ROOT=../PIN/
cd ..
wget -qO- http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz | tar xvz -C AFL/ --strip-components=1
cd AFL
make
