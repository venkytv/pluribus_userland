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

COMPONENT_NAME=		XML-Twig
COMPONENT_VERSION=	3.52
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_ARCHIVE_HASH=	\
    sha256:fef75826c24f2b877d0a0d2645212fc4fb9756ed4d2711614ac15c497e8680ad
COMPONENT_ARCHIVE_URL=	\
    https://cpan.metacpan.org/authors/id/M/MI/MIROD/$(COMPONENT_ARCHIVE)
COMPONENT_PROJECT_URL=	https://metacpan.org/release/XML-Twig
COMPONENT_BUGDB=	perl-mod/xml-twig

include $(WS_TOP)/make-rules/prep.mk
include $(WS_TOP)/make-rules/ips.mk
include $(WS_TOP)/make-rules/makemaker.mk

#
# Install all tools
#
PERL_MAKE_OPTIONS = -y

# Enable ASLR for this component
ASLR_MODE = $(ASLR_ENABLE)

# man pages go in the common area
COMPONENT_INSTALL_ENV += INSTALLVENDORMAN3DIR=$(USRSHAREMAN3DIR)

COMPONENT_TEST_TARGETS = test

build:		$(BUILD_32_and_64)

install:	$(INSTALL_32_and_64)

	#
	# Must have xml-parser installed for these tests to pass.
	#
test:		$(TEST_32_and_64)
