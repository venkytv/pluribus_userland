#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL)". You may
# only use this file in accordance with the terms of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2013, Andrzej Szeszo
# Copyright 2016, Adam Stevko
#

include ../../../make-rules/shared-macros.mk
include ../illumos-gate/version-macros.mk

COMPONENT_NAME=		g11n
COMPONENT_SRC=		$(COMPONENT_NAME)
PUB_SUFFIX=		.pluribusnetworks.com

GIT=git
GIT_REPO=anon@src.omniti.com:~omnios/core/g11n
GIT_BRANCH=omni
DMAKE=/usr/bin/dmake
FETCH=$(WS_TOOLS)/userland-fetch

DEBUG=no

COMPONENT_REVISION=$(shell cd $(COMPONENT_SRC); git rev-list HEAD --count)

$(SOURCE_DIR)/.downloaded: 
	@[ -d $(SOURCE_DIR) ] || \
	$(GIT) clone -b $(GIT_BRANCH) $(GIT_REPO) $(SOURCE_DIR)
	@cd $(SOURCE_DIR); $(GIT) log -1 --format=%H > .downloaded

update:
	@[ -d $(SOURCE_DIR) ] || \
	$(GIT) clone -b $(GIT_BRANCH) $(GIT_REPO) $(SOURCE_DIR)
	cd $(SOURCE_DIR); $(GIT) pull $(GIT_REPO); \
	  [ "$$($(GIT) log -1 --format=%H)" == "$$(cat .downloaded)" ] || \
	  $(GIT) log -1 --format=%H > .downloaded

download:: $(SOURCE_DIR)/.downloaded

prep::

build install: $(BUILD_DIR)/$(MACH)/.built

$(BUILD_DIR)/$(MACH)/.built: $(SOURCE_DIR)/.downloaded
	mkdir -p $(BUILD_DIR)/$(MACH)
	(cd $(SOURCE_DIR); \
	 echo "-------- toplevel build --------"; \
	 export SRC=$(SOURCE_DIR); \
	 $(DMAKE); \
	 $(DMAKE); \
	 $(DMAKE); \
	 $(DMAKE); \
	 $(DMAKE); if [ $$? -ne 0 ]; then exit 1; fi; \
	 $(DMAKE) install; if [ $$? -ne 0 ]; then exit 1; fi; \
	 mkdir -p $SRC/proto/i386/fileroot/usr/share/man/man5/; \
	 cp $(COMPONENT_DIR)/files/iconv_en_US.UTF-8.5 \
		$SRC/proto/i386/fileroot/usr/share/man/man5/iconv_en_US.UTF-8.5)
	$(TOUCH) $@

$(BUILD_DIR)/$(MACH)/.published: $(BUILD_DIR)/$(MACH)/.built
	(cd $(SOURCE_DIR)/pkg; \
	 grep -- "--version 3" Makefile > /dev/null; \
	 if [ $$? -eq 0 ]; then $(GSED) -i 's/--version 3//' Makefile; fi; \
	 grep -- "pkgrepo set" Makefile > /dev/null; \
	 if [ $$? -eq 0 ]; then \
		$(GSED) -i 's/pkgrepo set/pkgrepo/' Makefile; \
		$(GSED) -i 's@publisher/prefix=@set publisher/prefix=@' Makefile; \
	 fi; \
	 echo "-------- Building packages --------"; \
	 ISALIST=i386 CC=gcc $(DMAKE) PKGARCHIVE=$(SOURCE_DIR) SRC=$(SOURCE_DIR) CLOSED_BUILD=no L10N_BUILDNUM=$(ONNV_BUILDNUM); \
	 ISALIST=i386 CC=gcc $(DMAKE) publish_pkgs PKGARCHIVE=$(SOURCE_DIR) SRC=$(SOURCE_DIR) CLOSED_BUILD=no \
		L10N_BUILDNUM=$(ONNV_BUILDNUM) PKGPUBLISHER_REDIST=$(PUBLISHER)$(PUB_SUFFIX); \
	 cd $(SOURCE_DIR); \
	 echo "-------- Rebuilding repository metadata --------"; \
	 pkgrepo -s file://$(SOURCE_DIR)/repo.redist rebuild; \
	 echo "-------- Re-publishing g11n pkgs to $(WS_REPO) --------"; \
	 $(RM) -r $(@D)/pkgrecv.dir; \
	 $(MKDIR) $(@D)/pkgrecv.dir; \
	 pkgrecv -s file://$(SOURCE_DIR)/repo.redist -d $(@D)/pkgrecv.dir 'pkg:/*'; \
	 for pkg in $$(echo $(@D)/pkgrecv.dir/*/*); do \
		echo "Re-publishing $$pkg ..."; \
		pkgsend -s file://$(WS_REPO) publish --fmri-in-manifest --no-index --no-catalog -d $$pkg $$pkg/manifest; \
	 done; \
	 pkgrepo -s file://$(WS_REPO) rebuild)
	$(TOUCH) $@

.NOTPARALLEL:

publish: $(BUILD_DIR)/$(MACH)/.published

clean::
	$(RM) -r $(BUILD_DIR)

