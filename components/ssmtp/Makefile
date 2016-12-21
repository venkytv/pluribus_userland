#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright (c) 2011, 2012, Oracle and/or its affiliates. All rights reserved.
#
include ../../make-rules/shared-macros.mk

COMPONENT_NAME=		ssmtp
COMPONENT_VERSION=	2.64
COMPONENT_PROJECT_URL=	https://github.com/badoo/ssmtp
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=      $(COMPONENT_NAME)_$(COMPONENT_VERSION).orig.tar.bz2
COMPONENT_ARCHIVE_HASH=	\
    sha256:22c37dc90c871e8e052b2cab0ad219d010fa938608cd66b21c8f3c759046fa36
COMPONENT_ARCHIVE_URL=      http://http.debian.net/debian/pool/main/s/$(COMPONENT_NAME)/$(COMPONENT_ARCHIVE)
COMPONENT_BUGDB=	utility/ssmtp
COMPONENT_PATCHES =

COMPONENT_ARCHIVE_1=    $(COMPONENT_NAME)_$(COMPONENT_VERSION)-8.debian.tar.bz2
COMPONENT_ARCHIVE_HASH_1= \
    sha256:2ed9caf0a14d4d5a44837a4a76cd5c9a52e527e2eb7a300eb328d90cc97917f0
COMPONENT_ARCHIVE_URL_1= http://http.debian.net/debian/pool/main/s/$(COMPONENT_NAME)/$(COMPONENT_ARCHIVE_1)

include ../../make-rules/prep.mk
include ../../make-rules/configure.mk
include ../../make-rules/ips.mk

COMPONENT_PREP_ACTION = \
	(cd $(@D) ; gtar jxf $(COMPONENT_DIR)/$(COMPONENT_ARCHIVE_1));

COMPONENT_PRE_CONFIGURE_ACTION = ( cp -r $(SOURCE_DIR)/* $(@D); \
	cd $(SOURCE_DIR); $(GSED) -i -e 's/-lssl/-lssl -lcrypto/g' configure);

COMPONENT_POST_CONFIGURE_ACTION = (cd $(@D) ; \
	$(GPATCH) -p1 < debian/patches/02-557725-solaris.patch; \
	);

# This doesn't respect DESTDIR, so overload BINDIR and MANDIR when we install.
COMPONENT_INSTALL_ARGS += prefix=$(PROTOUSRDIR)
COMPONENT_INSTALL_ARGS += GEN_CONFIG=/bin/true
COMPONENT_INSTALL_ARGS += etcdir=$(PROTOETCDIR)
COMPONENT_INSTALL_ARGS += mandir=$(PROTOUSRSHAREMAN8DIR)

CONFIGURE_OPTIONS  =	--enable-ssl

build:		$(BUILD_32)

install:	$(INSTALL_32)

test:		$(TEST_32)

BUILD_PKG_DEPENDENCIES =	$(BUILD_TOOLS)

include ../../make-rules/depend.mk
