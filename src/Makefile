#CC=icc
#CC=clang
CC=gcc-mp-4.7
#CC=llvm-gcc
CXX=$(CC)
#CXX=llvm-g++
#CXX=g++
#CFLAGS=-msse4 -march=corei7 -mtune=corei7-sse4
#CFLAGS=-march=corei7 -mtune=corei7
#CFLAGS=-mtune=generic
#CFLAGS=-march=corei7-avx -mtune=corei7-avx -mavx
#CFLAGS=-march=native -mtune=native -mavx
# * good for icc + sse4
#CFLAGS=-march=corei7 -mtune=corei7 -axSSE4.2
# * good for icc + avx
#CFLAGS=-march=corei7-avx -mtune=corei7-avx -axAVX

CFLAGS+= -O3
#CFLAGS+= -g

CFLAGS+= -DUNROLL_LOOPS
CFLAGS+= -DPROFILE
#CFLAGS+= -DPROFILE_SHA

# SPH does not support intel (no 64 bit types)
#CFLAGS+= -DUSE_SPH
CFLAGS+= -DUSE_ASM -DAVX
#CFLAGS+= -DUSE_ASM -DSSE4
#CFLAGS+= -DUSE_OPENSSL

obj=sph_sha2.o sph_sha2big.o jhlib.o main.o transaction.o \
		xptClient.o xptClientPacketHandler.o xptPacketbuffer.o xptServer.o \
		xptServerPacketHandler.o \
		sha2.o sha512_sse4.o sha512_avx.o  sha512.o sha512_avx2_rorx.o \
		sha256_ssse3_glue.o sha256_sse4.o sha256_avx1.o sha256_avx2_rorx8.o \
		yvg_protosharesMiner.o
		
obj+= win.o

app=jhProtominer

all: $(app)

.cpp.o: 
	$(CXX) $(CFLAGS) -c -o $@ $<

.c.o: 
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: intel/%.asm
	yasm -f macho64 -D__APPLE__ -o $@ $<

%.o: intel/%.S
	$(CC) $(CFLAGS) -c -o $@ $<

jhProtominer: $(obj)
	$(CXX) $(LDFLAGS) -o $@ $(obj) -lpthread -lcrypto
	#$(CXX) $(LDFLAGS) -o $@ $(obj) libcrypto.a -lpthread

clean:
	$(RM) *.o $(app)

.PHONY: all clean
