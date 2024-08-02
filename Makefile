PROJECTROOT    ?= .
#BUILDROOT      ?= $(PROJECTROOT)/build
#CSHAREDDIR     ?= $(PROJECTROOT)/cshared
#FSCRYPTDIR     ?= $(PROJECTROOT)/fscrypt

all: install
clean:
	-make -C lib clean
ifeq (.,$(PROJECTROOT))
	-make -C tests clean
	-make -C cshared clean
	-make -C fscrypt clean
endif

tests: install FORCE
	make -C $@ all PROJECTROOT=..

install: cshared fscrypt FORCE
	make -C lib all PROJECTROOT=$(PROJECTROOT)/..

cshared: FORCE
	make -C $@ all PROJECTROOT=$(PROJECTROOT)/..

fscrypt: FORCE
	make -C $@ all PROJECTROOT=$(PROJECTROOT)/..

FORCE:
