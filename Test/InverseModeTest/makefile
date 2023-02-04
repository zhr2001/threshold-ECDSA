CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

InverseModeTest: InverseModeTest.o ECDSA.o
	$(CXX) -o InverseModeTest InverseModeTest.o ECDSA.o -lgmp -lssl -lcrypto

InverseModeTest.o: $(DEPS) InverseModeTest.cpp
	$(CXX) -c -g InverseModeTest.cpp

ECDSA.o: $(DEPS) ../../util/ECDSA.cpp
	$(CXX) -c -g ../../util/ECDSA.cpp

clean:
	rm -rf *.o *Test