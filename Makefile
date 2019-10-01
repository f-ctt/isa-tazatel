CPP=g++
CPPFLAGS= -Wextra -Wall -std=c++17

isa-tazatel: 
	$(CPP) -o $@ $@.cpp $(CPPFLAGS)
