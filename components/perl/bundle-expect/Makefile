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

include ../../../make-rules/shared-macros.mk

COMPONENT_NAME=		Bundle-Expect
COMPONENT_VERSION=	1.0.9
COMPONENT_ARCHIVE_VERSION = 1.09
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_ARCHIVE_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_ARCHIVE_HASH=	\
    sha256:fa6936177c93a483c160023a9fa66939c954767a036341c926e73b616b95f20e
COMPONENT_ARCHIVE_URL=	\
    https://cpan.metacpan.org/authors/id/R/RG/RGIERSIG/$(COMPONENT_ARCHIVE)
COMPONENT_PROJECT_URL=	https://metacpan.org/release/Bundle-Expect
COMPONENT_BUGDB=	perl-mod/bundle-expect

include $(WS_TOP)/make-rules/prep.mk
include $(WS_TOP)/make-rules/ips.mk
include $(WS_TOP)/make-rules/makemaker.mk

# Enable ASLR for this component
ASLR_MODE = $(ASLR_ENABLE)

# man pages go in the common area
COMPONENT_INSTALL_ENV += INSTALLVENDORMAN3DIR=$(USRSHAREMAN3DIR)

COMPONENT_TEST_TARGETS = test

build:		$(BUILD_32_and_64)

install:	$(INSTALL_32_and_64)

test:		$(TEST_32_and_64)
