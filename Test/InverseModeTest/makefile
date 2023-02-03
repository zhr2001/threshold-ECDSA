CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

InverseModeTest: InverseModeTest.o ECDSA.o
	g++ -o InverseModeTest InverseModeTest.o ECDSA.o -lgmp

InverseModeTest.o: $(DEPS) InverseModeTest.cpp
	g++ -c InverseModeTest.cpp

ECDSA.o: $(DEPS) ../../util/ECDSA.cpp
	g++ -c ../../util/ECDSA.cpp