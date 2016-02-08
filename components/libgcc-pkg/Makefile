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

#
# Copyright (c) 2011, 2014, Oracle and/or its affiliates. All rights reserved.
#

include ../../make-rules/shared-macros.mk

COMPONENT_NAME=		gcc-libgcc
COMPONENT_VERSION=	4.8.5
COMPONENT_PROJECT_URL=	https://gcc.gnu.org/
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_NAME)-$(COMPONENT_VERSION).src.tgz
COMPONENT_ARCHIVE_HASH=	\
    sha256:f46cbb14db855ee07f1334ca54ea24b284207e9f8be96fbe813169df1f4fe354
COMPONENT_ARCHIVE_URL=  http://$(PN_PKG_FILES)/$(COMPONENT_ARCHIVE)

include ../../make-rules/prep.mk
include ../../make-rules/configure.mk
include ../../make-rules/ips.mk

COMPONENT_PRE_CONFIGURE_ACTION =  \
        ($(CLONEY) $(SOURCE_DIR) $(@D))

CFLAGS += "-Dinline"
CFLAGS += -I/usr/include/ncurses

LDFLAGS.32 = -L/usr/gnu/lib -R/usr/gnu/lib
LDFLAGS.64 = -L/usr/gnu/lib/$(MACH64) -R/usr/gnu/lib/$(MACH64)
LDFLAGS += $(LDFLAGS.$(BITS))

ASLR_MODE = $(ASLR_ENABLE)

# common targets
build:		$(BUILD_32_and_64)

install:	$(INSTALL_32_and_64)

test:		$(NO_TESTS)

BUILD_PKG_DEPENDENCIES =	$(BUILD_TOOLS)

include ../../make-rules/depend.mk
