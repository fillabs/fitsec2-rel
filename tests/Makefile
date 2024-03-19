PROJECTROOT    = ../..
BUILDROOT      = $(PROJECTROOT)/build

ifeq (,$(FITSEC2))
  FITSEC2 = ..
endif
ifeq (,$(FSPKI))
  FSPKI = ..
endif

ifeq (,$(TEST_BIN))

ifeq ($(ARCH),MSVC)
  outdir = $(BUILDROOT)/MSVC-x64-Debug
else
  ifneq (no,$(DEBUG))
    outdir = $(BUILDROOT)/$(shell gcc -dumpmachine)-d
  else
    outdir = $(BUILDROOT)/$(shell gcc -dumpmachine)
  endif
endif

TESTS = $(filter-out test_engine, $(basename $(wildcard *.vcxproj)))

POOLS = POOL_1 POOL_2 POOL_3 POOL_2_P2P

POOL_1     = CERT_IUT_A_RCA.oer CERT_IUT_A_AA.oer CERT_IUT_A_AT.oer  CERT_IUT_A_AT.vkey  CERT_IUT_A_AT.ekey
POOL_2     = CERT_IUT_A_RCA.oer CERT_IUT_A_AA.oer CERT_IUT_A1_AT.oer CERT_IUT_A1_AT.vkey CERT_IUT_A1_AT.ekey
POOL_3     = CERT_IUT_A_RCA.oer CERT_IUT_A_AA.oer CERT_IUT_A2_AT.oer CERT_IUT_A2_AT.vkey CERT_IUT_A2_AT.ekey

POOL_2_P2P = CERT_IUT_A_RCA.oer CERT_IUT_A_B_AA.oer CERT_IUT_A_B_AT.oer  CERT_IUT_A_B_AT.vkey  CERT_IUT_A_B_AT.ekey


POOLFILES = $(foreach p, $(POOLS), $(addprefix $(outdir)/$(p)/,$($(p))))

all: $(addprefix all_, $(TESTS))
install: $(addprefix install_, $(TESTS)) 

clean: $(addprefix clean_, $(TESTS))

$(addprefix clean_, $(TESTS)): clean_% :
	-make TEST_BIN=$* clean

$(addprefix all_, $(TESTS)): all_% :
	-make TEST_BIN=$* all

$(addprefix install_, $(TESTS)): install_% :
	-make TEST_BIN=$* install

forcepool: pool_clean pool
pool_clean:
	rm -rf $(addprefix $(outdir)/, $(POOLS))

pool: $(addprefix $(outdir)/, $(POOLS)) $(POOLFILES)

$(addprefix $(outdir)/, $(POOLS)):
	mkdir -p $@

define PoolRule
$$(addprefix $$(outdir)/$(strip $1)/, $$($(strip $1))): $$(outdir)/$(strip $1)/%: ../data/certificates/% 
	cp -f $$< $$@
endef

$(foreach P,$(POOLS),$(eval $(call PoolRule, $(P))))

else
CSHAREDDIR     = $(PROJECTROOT)/cshared
PROJECT        = fitsec_tests
DEBUG          = yes
bins           = $(TEST_BIN)
sources       := $(TEST_BIN).c load_certs.c utils.c
includes      += . $(FITSEC2) $(FSPKI) $(PROJECTROOT)/fscrypt
packages      += openssl cshared
deps           = $(outdir)/libfitsec2.a $(outdir)/libfspki.a
libs           = $(outdir)/libfspki.a $(outdir)/libfitsec2.a -Wl,--whole-archive $(outdir)/libfscrypt.a -Wl,--no-whole-archive -lm -lpthread
ifeq (test_pcap, $(TEST_BIN))
 NPCAP_SDK := /cygdrive/c/PROGRA~1/Npcap/sdk
 packages     += pcap
endif

ifneq (,$(strip $(findstring $(TEST_BIN), test_ctlcrl test_pki test_auth)))
 packages     += curl
endif

include $(CSHAREDDIR)/common.mk
endif

