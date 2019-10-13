CPP=g++
CPPFLAGS= -Wextra -Wall -std=c++1z

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CPP=g++-9
endif

isa-tazatel: isa-tazatel.cpp
	$(CPP) -o $@ $@.cpp $(CPPFLAGS) -O2 -lresolv -pthread

debug: isa-tazatel.cpp
	$(CPP) -o isa-tazatel $^ $(CPPFLAGS) -g -DDEBUG -lresolv -pthread

clean:
	rm isa-tazatel