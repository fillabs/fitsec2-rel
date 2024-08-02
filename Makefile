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

install: cshared-i fscrypt-i FORCE
	make -C lib all

cshared-i: FORCE
	make -C $(CSHAREDDIR) all

fscrypt-i: FORCE
	make -C $(FSCRYPTDIR) all

FORCE:
