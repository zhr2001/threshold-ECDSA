CXX = g++
CFLAGS = -I.
DEPS = ../../include/SecretSharing.h

SSSTest: SSSTest.o SecretSharing.o
	$(CXX) -o SSSTest SSSTest.o SecretSharing.o -lgmp

SSSTest.o: $(DEPS) SSSTest.cpp
	$(CXX) -c -g SSSTest.cpp

SecretSharing.o: $(DEPS) ../../util/SecretSharing.cpp
	$(CXX) -c -g ../../util/SecretSharing.cpp

clean:
	rm -rf *.o *Test