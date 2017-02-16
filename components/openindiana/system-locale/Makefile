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
# Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
#

include ../../../make-rules/shared-macros.mk
include ../illumos-gate/version-macros.mk

COMPONENT_NAME=		locale
COMPONENT_VERSION=	0.5.11
COMPONENT_FMRI=		system/locale
COMPONENT_SUMMARY=	language support common components (obsolete)
COMPONENT_LICENSE=	CDDL
SOURCE_DIR=		locale

include $(WS_MAKE_RULES)/prep.mk
include $(WS_MAKE_RULES)/configure.mk
include $(WS_MAKE_RULES)/ips.mk

PKGSEND_PUBLISH_OPTIONS += --no-index --no-catalog
PKG_MACROS += -D PKG_BUILD_VERSION=$(PKG_BUILD_VERSION)
PKG_MACROS += -D NVOS_MINOR=$(NVOS_MINOR)

dirs:
	$(MKDIR) $(SOURCE_DIR)
	$(MKDIR) $(BUILD_DIR_32)
	$(TOUCH) $(BUILD_DIR_32)/.prep

install: dirs
	$(TOUCH) $(BUILD_DIR_32)/.installed

publish:	build install $(PUBLISH_STAMP)
	pkgrepo -s file://$(WS_REPO) rebuild

clean::
	$(RM) -r $(BUILD_DIR)
	$(RM) -r $(SOURCE_DIR)

include $(WS_MAKE_RULES)/depend.mk
