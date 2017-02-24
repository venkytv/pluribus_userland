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

PATH=$(dir $(CC)):$(JAVA_HOME)/bin:/usr/bin:/usr/gnu/bin

COMPONENT_NAME=		idnkit
COMPONENT_VERSION=	1.0-src
IPS_COMPONENT_VERSION=	1.0
COMPONENT_SUMMARY=	Internationalized Domain Name kit (idnkit/JPNIC)
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_PROJECT_URL=	http://www.gnu.org/software/libidn/
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_ARCHIVE_HASH=	\
    sha256:16cd5fce81a5180d6a2c61cf20572668b3dc59f5c39c272b75fa98edab3391fc
COMPONENT_ARCHIVE_URL=  https://www.nic.ad.jp/ja/idn/idnkit/download/sources/$(COMPONENT_ARCHIVE)
COMPONENT_FMRI=		library/idnkit
COMPONENT_CLASSIFICATION=	org.opensolaris.category.2008:System/Internationalization
COMPONENT_LICENSE=	BSD

include $(WS_MAKE_RULES)/prep.mk
include $(WS_MAKE_RULES)/configure.mk
include $(WS_MAKE_RULES)/ips.mk

CONFIGURE_OPTIONS.32  = --prefix=/usr --mandir=/usr/share/man --bindir=/usr/bin --libdir=/usr/lib \
	--sbindir=/usr/sbin --disable-static --mandir=/usr/share/man
CONFIGURE_OPTIONS.64  = --prefix=/usr --mandir=/usr/share/man --bindir=/usr/bin/$(MACH64) \
	--libdir=/usr/lib/$(MACH64) --sbindir=/usr/sbin --disable-static --mandir=/usr/share/man
CONFIGURE_OPTIONS=$(CONFIGURE_OPTIONS.$(BITS))

build: $(BUILD_32_and_64)

install: $(INSTALL_32_and_64)

test: $(TEST_32_and_64)

REQUIRED_PACKAGES += system/library

include $(WS_MAKE_RULES)/depend.mk
