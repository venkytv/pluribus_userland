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
# Copyright (c) 2013, Oracle and/or its affiliates. All rights reserved.
#
include ../../../make-rules/shared-macros.mk

#
# Note this perl is 32-bit only.
#

# I want to override PERL_VERSION and PERL_ARCH because when building
# a new version of perl it probably isn't installed so shared-macros.mk
# can't call it.

COMPONENT_NAME=         mgmt-sysidtool
COMPONENT_VERSION=      3.0
COMPONENT_SUMMARY=      Obsolete Sun Sysidtool
COMPONENT_PROJECT_URL=  http://www.illumos.org/
COMPONENT_CLASSIFICATION=       System/Core
COMPONENT_SRC=          $(COMPONENT_NAME)-$(COMPONENT_VERSION)

include $(WS_TOP)/make-rules/prep.mk
include $(WS_TOP)/make-rules/ips.mk

build:
	pwd
	mkdir -p $(COMPONENT_SRC)

install:

test:

clean::
	$(RM) -r $(BUILD_DIR)

