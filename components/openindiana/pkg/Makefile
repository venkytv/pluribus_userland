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

COMPONENT_NAME=         pkg
COMPONENT_VERSION=      0.5.11
COMPONENT_SUMMARY=      The Image packaging system.
COMPONENT_DESCRIPTION=  The Image packaging system is the software delivery system on OpenSolaris and derivatives.
COMPONENT_PROJECT_URL=  http://www.illumos.org/
COMPONENT_CLASSIFICATION=       System/Core
COMPONENT_SRC=          $(COMPONENT_NAME)-$(COMPONENT_VERSION)

include $(WS_TOP)/make-rules/prep.mk
include $(WS_TOP)/make-rules/ips.mk

build:
	mkdir -p $(COMPONENT_SRC)

install:
	mkdir -p $(PROTO_DIR)
	cp -rp pkg_src/src/* $(PROTO_DIR)
	mkdir -p $(PROTO_DIR)/usr/lib/python2.6
	cp -rp $(PROTO_DIR)/usr/lib/python2.7/* $(PROTO_DIR)/usr/lib/python2.6/
	mv $(PROTO_DIR)/usr/lib/python2.6/vendor-packages/pkg-0.1-py2.7.egg-info \
	   $(PROTO_DIR)/usr/lib/python2.6/vendor-packages/pkg-0.1-py2.6.egg-info
	$(PYTHON.2.7.32) -m compileall $(PROTO_DIR)/usr/lib/python2.7/vendor-packages
	$(PYTHON.2.6.32) -m compileall $(PROTO_DIR)/usr/lib/python2.6/vendor-packages

test:

clean::
	$(RM) -r $(BUILD_DIR)

