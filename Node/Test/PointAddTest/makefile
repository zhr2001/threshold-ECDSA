CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

PointAddTest: PointAddTest.o ECDSA.o
	$(CXX) -o PointAddTest PointAddTest.o ECDSA.o -lgmp -lssl -lcrypto

PointAddTest.o: $(DEPS) PointAddTest.cpp
	$(CXX) -c -g PointAddTest.cpp

ECDSA.o: $(DEPS) ../../util/ECDSA.cpp
	$(CXX) -c -g ../../util/ECDSA.cpp

clean:
	rm -rf *.o *Test