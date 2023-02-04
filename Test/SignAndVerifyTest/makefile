CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

SignAndVerifyTest: SignAndVerifyTest.o ECDSA.o
	$(CXX) -o SignAndVerifyTest SignAndVerifyTest.o ECDSA.o -lgmp -lssl -lcrypto

SignAndVerifyTest.o: $(DEPS) SignAndVerifyTest.cpp
	$(CXX) -c -g SignAndVerifyTest.cpp

ECDSA.o: $(DEPS) ../../util/ECDSA.cpp
	$(CXX) -c -g ../../util/ECDSA.cpp

clean:
	rm -rf *.o *Test