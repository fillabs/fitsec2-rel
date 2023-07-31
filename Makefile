export PROJECTROOT    ?= .
export BUILDROOT      ?= $(PROJECTROOT)/build
export CSHAREDDIR     ?= $(PROJECTROOT)/cshared
export FSCRYPTDIR     ?= $(PROJECTROOT)/fscrypt

all: install
clean:
	-make -C lib clean
ifeq (.,$(PROJECTROOT))
	-make -C tests clean
	-make -C cshared clean
	-make -C fscrypt clean
endif

tests: install FORCE
	make -C $@ all

install: cshared fscrypt FORCE
	make -C lib all

cshared: FORCE
	make -C $@ all

fscrypt: FORCE
	make -C $@ all

FORCE:
