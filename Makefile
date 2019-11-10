CPP=g++
CPPFLAGS= -Wextra -Wall -std=c++1z
LIBS= -lresolv -pthread

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CPP=clang++
endif

DEPS = dns_resolver.h whois.h helpers.h
OBJ = dns_resolver.o whois.o isa-tazatel.o helpers.o

all: CPPFLAGS += -O2
all: isa-tazatel

debug: CPPFLAGS += -g -ggdb3 -DDEBUG
debug: isa-tazatel

.PHONY: clean

%.o: %.c $(DEPS)
	$(CPP) -o -c $@ $@.cpp $(CPPFLAGS) $(LIBS)

isa-tazatel: $(OBJ)
	$(CPP) -o isa-tazatel $^ $(CPPFLAGS) $(LIBS)

clean:
	rm ./*.o