CC=llvm-gcc
#CFLAGS=-O3 -mavx -msse4 -march=corei7 -tune=corei7avx
CFLAGS=-Os -O3 -fomit-frame-pointer -march=native -tune=corei7avx -mavx
#CFLAGS=-Os -fomit-frame-pointer -march=native -tune=corei7sse4 -msse4

#CFLAGS+= -DUSE_SPH
CFLAGS+= -DUSE_ASM -DAVX
#CFLAGS+= -DUSE_ASM -DSSE4
CFLAGS+= -DUSE_OPENSSL

obj=sph_sha2.o sph_sha2big.o jhlib.o main.o protosharesMiner.o sha2.o transaction.o xptClient.o xptClientPacketHandler.o xptPacketbuffer.o xptServer.o xptServerPacketHandler.o win.o sha512_sse4.o sha512_avx.o sha512.o

app=jhProtominer

all: $(app)

.cpp.o: 
	$(CXX) $(CFLAGS) -c -o $@ $<

.c.o: 
	$(CXX) $(CFLAGS) -c -o $@ $<

%.o: intel/%.asm
	yasm -f macho64 -o $@ $<

jhProtominer: $(obj)
	$(CXX) $(LDFLAGS) -o $@ $(obj) -lpthread -lcrypto
	#$(CXX) $(LDFLAGS) -o $@ $(obj) libcrypto.a -lpthread

clean:
	$(RM) *.o $(app)

.PHONY: all clean
