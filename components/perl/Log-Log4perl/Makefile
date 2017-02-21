#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2013 Alexander Pyhalov.  All rights reserved.
#

include ../../../make-rules/shared-macros.mk

COMPONENT_NAME=		Log-Log4perl
COMPONENT_VERSION=	1.49
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_PROJECT_URL=	https://metacpan.org/pod/Log::Log4perl
COMPONENT_ARCHIVE_HASH=	\
    sha256:b739187f519146cb6bebcfc427c64b1f4138b35c5f4c96f46a21ed4a43872e16
COMPONENT_ARCHIVE_URL=	https://cpan.metacpan.org/authors/id/M/MS/MSCHILLI/$(COMPONENT_ARCHIVE)

include $(WS_MAKE_RULES)/prep.mk
include $(WS_MAKE_RULES)/makemaker.mk
include $(WS_MAKE_RULES)/ips.mk

COMPONENT_TEST_TARGETS = test

build:		$(BUILD_32_and_64)

install:	$(INSTALL_32_and_64)

test:		$(TEST_32_and_64)
