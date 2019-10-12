CPP=g++
CPPFLAGS= -Wextra -Wall -std=c++17

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CPP=g++-9
endif

isa-tazatel: 
	$(CPP) -o $@ $@.cpp $(CPPFLAGS)
