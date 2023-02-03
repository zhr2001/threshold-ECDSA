CXX = g++
CFLAGS = -I.
DEPS = ../../include/ECDSA.h

ISOnCurveTest: ISOnCurveTest.o ECDSA.o
	$(CXX) -o ISOnCurveTest ISOnCurveTest.o ECDSA.o -lgmp

ISOnCurveTest.o: $(DEPS) ISOnCurveTest.cpp
	$(CXX) -c -g ISOnCurveTest.cpp

ECDSA.o: $(DEPS) ../../util/ECDSA.cpp
	$(CXX) -c -g ../../util/ECDSA.cpp

clean:
	rm -rf *.o *Test