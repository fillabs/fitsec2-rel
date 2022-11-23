PROJECTROOT  ?= ..
BUILDROOT    ?= $(PROJECTROOT)/build
PROJECT      = fitsec2
DEBUG        = yes
CSHAREDDIR   = $(PROJECTROOT)/cshared

ARCHD = $(ARCH)$(dsuffix)

lib_install  = $(wildcard $(ARCHD)/*)

include $(CSHAREDDIR)/common.mk

build_install = $(addprefix $(BUILDROOT)/, $(lib_install))

all: $(build_install)

clean: build_clean

build_clean:
	rm -f $(build_install)

$(build_install): $(BUILDROOT)/%: %
	cp -f $< $@
