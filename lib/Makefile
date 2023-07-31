PROJECTROOT  ?= ..
BUILDROOT    ?= $(PROJECTROOT)/build
PROJECT      ?= fitsec2
DEBUG        ?= yes
CSHAREDDIR   ?= $(PROJECTROOT)/cshared

ifeq ($(ARCH),)
 ARCH = $(shell gcc -dumpmachine)
endif

ifeq (,$(wildcard $(ARCH)))
  $(error Architecture $(ARCH) is not supported)
endif

lib_install  = $(wildcard $(ARCH)/*)

ifneq ($(DEBUG),no)
  dsuffix = -d
endif

ARCHD = $(ARCH)$(dsuffix)

build_install = $(patsubst $(ARCH)/%, $(BUILDROOT)/$(ARCHD)/%, $(lib_install))

all: $(build_install)

clean: build_clean

build_clean:
	rm -f $(build_install)

$(build_install): $(BUILDROOT)/$(ARCHD)%: $(ARCH)/%
	cp -f $< $@
