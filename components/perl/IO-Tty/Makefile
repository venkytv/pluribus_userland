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

COMPONENT_NAME=		IO-Tty
COMPONENT_VERSION=	1.12
COMPONENT_SRC=		$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_ARCHIVE=	$(COMPONENT_SRC).tar.gz
COMPONENT_PROJECT_URL=	https://metacpan.org/pod/IO::Tty
COMPONENT_ARCHIVE_HASH=	\
    sha256:a2ef8770d3309178203f8c8ac25e623e63cf76e97830fd3be280ade1a555290d
COMPONENT_ARCHIVE_URL=	https://cpan.metacpan.org/authors/id/T/TO/TODDR/$(COMPONENT_ARCHIVE)

include $(WS_MAKE_RULES)/prep.mk
include $(WS_MAKE_RULES)/makemaker.mk
include $(WS_MAKE_RULES)/ips.mk

COMPONENT_TEST_TARGETS = test

build:		$(BUILD_32_and_64)

install:	$(INSTALL_32_and_64)

test:		$(TEST_32_and_64)
