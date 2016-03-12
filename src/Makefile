#for GNU make

#DDEBUG = -O0 -g -ggdb -DDEBUG=1

CC = g++
#CC = clang++
#CC = icc
#ICCOPT = -fvisibility=hidden -fvisibility-inlines-hidden
SSE = -DHAVE_SSE2 -msse2
#SSE = -DHAVE_SSE4 -msse4
ALIGN = -DUSER_DATA_ALIGNED
#SEP = -DSEPARATE_XOR
CCOPT = ${ICCOPT} ${SSE} ${SEP} ${ALIGN} -Wall -O3 $(DDEBUG) \
-I../include \
-D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS

all:  cryptfile

cryptfile: cryptfile.o cryptmt.o
	${CC} -o $@  cryptfile.o cryptmt.o

.cpp.o:
	${CC} ${CCOPT} -c $<

clean:
	rm -rf *.o *~ *.dSYM
