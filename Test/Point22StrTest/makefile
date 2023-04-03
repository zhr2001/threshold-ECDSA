CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

Point22StrTest: Point22StrTest.o ECDSA.o
	$(CXX) -o Point22StrTest Point22StrTest.o ECDSA.o -lgmp -lssl -lcrypto

Point22StrTest.o: $(DEPS) Point22StrTest.cpp
	$(CXX) -c -g Point22StrTest.cpp

ECDSA.o: $(DEPS) ../../TrustedGMPUtil/ECDSA.cpp
	$(CXX) -c -g ../../TrustedGMPUtil/ECDSA.cpp

clean:
	rm -rf *.o *Test