#CC=llvm-gcc
#CFLAGS=-O3 -mavx -msse4 -march=corei7 -tune=corei7avx
#CFLAGS=-march=native -mtune=corei7avx -mavx
CFLAGS=-march=barcelona -mtune=barcelona

CFLAGS+= -O3
		
CFLAGS+= -DUNROLL_LOOPS
CFLAGS+= -DUSE_SPH
#CFLAGS+= -DUSE_ASM -DAVX
#CFLAGS+= -DUSE_ASM -DSSE4
#CFLAGS+= -DUSE_OPENSSL

obj=sph_sha2.o sph_sha2big.o jhlib.o main.o yvg_protosharesMiner.o sha2.o transaction.o \
		xptClient.o xptClientPacketHandler.o xptPacketbuffer.o xptServer.o \
		xptServerPacketHandler.o sha512_sse4.o sha512_avx.o  sha512.o \
		sha256_ssse3_glue.o sha256_sse4.o sha256_avx1.o sha256_avx2_rorx8.o \
		sha512_avx2_rorx.o
		
obj+= win.o

app=jhProtominer

all: $(app)

.cpp.o: 
	$(CXX) $(CFLAGS) -c -o $@ $<

.c.o: 
	$(CXX) $(CFLAGS) -c -o $@ $<

%.o: intel/%.asm
	yasm -f Win64 -o $@ $<

%.o: intel/%.S
	$(CC) $(CFLAGS) -c -o $@ $<

jhProtominer: $(obj)
	$(CXX) $(LDFLAGS) -o $@ $(obj) -lpthread -lcrypto
	#$(CXX) $(LDFLAGS) -o $@ $(obj) libcrypto.a -lpthread

clean:
	$(RM) *.o $(app)

.PHONY: all clean
