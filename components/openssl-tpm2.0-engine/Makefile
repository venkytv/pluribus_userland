#
# Copyright 2016 Pluribus Networks Inc.
#

include ../../make-rules/shared-macros.mk

COMPONENT_NAME=		openssl-tpm2.0-engine
COMPONENT_VERSION=	1.0
COMPONENT_LICENSE=	BSD
COMPONENT_PROJECT_URL=	http://www.pluribusnetworks.com
COMPONENT_INLINE_SRC=	$(COMPONENT_NAME)-$(COMPONENT_VERSION)
COMPONENT_SRC=		build-src
COMPONENT_ARCHIVE=

include ../../make-rules/prep.mk
include ../../make-rules/configure.mk
include ../../make-rules/ips.mk

COMPONENT_PREP_ACTION =			(cp -rp $(COMPONENT_INLINE_SRC) $(@D))
COMPONENT_PRE_CONFIGURE_ACTION =	($(CLONEY) $(SOURCE_DIR) $(@D))

CONFIGURE_ENV.32 = ENGINESDIR=/lib/openssl/default/engines
CONFIGURE_ENV.64 = ENGINESDIR=/lib/openssl/default/engines/amd64

build: $(BUILD_32_and_64)

install: $(INSTALL_32_and_64)

include $(WS_MAKE_RULES)/depend.mk
