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
# Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
#

include ../../make-rules/shared-macros.mk

COMPONENT_NAME=		ipmitool
COMPONENT_VERSION=	1.8.11
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_PROJECT_URL=	http://sourceforge.net/projects/ipmitool/files/ipmitool/
COMPONENT_ARCHIVE_HASH=	\
	sha256:5612f4835d89a6f2cede588eef978a05d63435cf2646256300d9785d8020a13e
COMPONENT_ARCHIVE_URL=	$(COMPONENT_PROJECT_URL)$(COMPONENT_VERSION)/$(COMPONENT_ARCHIVE)
COMPONENT_BUGDB=	utility/tss

include ../../make-rules/prep.mk
include ../../make-rules/configure.mk
include ../../make-rules/ips.mk
include ../../make-rules/lint-libraries.mk

PATCH_LEVEL=0

LIBS=-lnsl -lsocket -lgen

CONFIGURE_OPTIONS += --bindir=/usr/sbin
CONFIGURE_OPTIONS += --sbindir=/usr/lib
CONFIGURE_OPTIONS += --mandir=/usr/share/man
CONFIGURE_OPTIONS += --enable-intf-free=no
CONFIGURE_OPTIONS += --enable-intf-bmc=yes
CONFIGURE_OPTIONS += --enable-solaris-opt
CONFIGURE_OPTIONS += CFLAGS="$(CFLAGS) -fno-strict-aliasing"
CONFIGURE_OPTIONS += LIBS="$(LIBS)"

# Enable ASLR for this component
ASLR_MODE = $(ASLR_ENABLE)

# common targets
build:		$(BUILD_32)

install:	$(INSTALL_32)

test:		$(NO_TESTS)

BUILD_PKG_DEPENDENCIES =	$(BUILD_TOOLS)

include ../../make-rules/depend.mk
