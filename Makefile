SHELL := /bin/sh
MAKEFLAGS := -j8

CPLUS := g++

INC += -I. -DNDEBUG

COPT += -pg -g0 -O6 -m64 -Wall -msse3 -Wextra -Wformat -pedantic -std=c++0x
COPT += -ffast-math -fno-check-new -funroll-loops -Wno-deprecated
COPT += -fstrict-aliasing -Wformat-security -Wstrict-aliasing=2
COPT += -Wno-variadic-macros -Wno-unused-variable -Wno-unused-parameter

LIBS := -lcrypto -ldl

SOURCES := $(wildcard *.cpp cb/*.cpp)
OBJS := $(addprefix .objs/, $(notdir $(SOURCES:.cpp=.o)))

export

all: parser

env:
	$@

.objs/%.o: %.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	$(CPLUS) -MD $(CXXFLAGS) $(INC) $(COPT) -c $< -o $@
	mv -f $(@:.o=.d) .deps

.objs/%.o: cb/%.cpp
	@mkdir -p .deps
	@mkdir -p .objs
	$(CPLUS) -MD $(CXXFLAGS) $(INC) $(COPT) -c $< -o $@
	mv -f $(@:.o=.d) .deps

parser: $(OBJS)
	$(CPLUS) $(LOPT) $(COPT) -o parser $(OBJS) $(LIBS)

clean:
	-rm -r -f *.o *.i .objs .deps *.d parser

%.test: %.py
	python3 ./$<
%.run: %.py
	./$<
%.doctest: %.py
	python3 -m doctest $<
doctest: script.doctest blockparse.doctest
-include .deps/*
