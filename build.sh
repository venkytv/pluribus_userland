#!/bin/sh

component=$1
action=$2

WS_TOP=`pwd`
#USERLAND_GIT_REMOTE=`git remote show origin | grep -v 'Push' | sed -n 's/.*URL: //p'`
USERLAND_GIT_REMOTE='https://github.com/PluribusNetworks/pluribus_userland.git'
USERLAND_GIT_REV=`git rev-parse HEAD`
BUILD_VERSION="5.11-0.134"


if [ "x$component" = "xclean" ]
then
	rm -rf i386
        rm .setup
	rm tools/*.o
	rm tools/*.so
	action=clean

elif [ "x$component" = "xbuild" ]
then
	action=build

elif [ "x$component" = "xinstall" ]
then
	action=install

elif [ "x$component" != "x" ]
then
	cd components/$component
	[ $? -ne 0 ] && exit 1
fi

if [ "x$action" = "x" ]
then
	action=publish
fi

if [ ! -f .setup -a $action != clean ]
then
	(cd $WS_TOP
	gmake setup WS_TOP=$WS_TOP USERLAND_GIT_REMOTE=$USERLAND_GIT_REMOTE USERLAND_GIT_BRANCH=master USERLAND_GIT_REV=$USERLAND_GIT_REV BUILD_VERSION=$BUILD_VERSION
	[ $? -ne 0 ] && exit 1
	touch .setup)
	[ $? -ne 0 ] && exit 1
fi

gmake $action WS_TOP=$WS_TOP USERLAND_GIT_REMOTE=$USERLAND_GIT_REMOTE USERLAND_GIT_BRANCH=master USERLAND_GIT_REV=$USERLAND_GIT_REV BUILD_VERSION=$BUILD_VERSION

