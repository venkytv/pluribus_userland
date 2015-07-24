#!/bin/sh
#
# COPYRIGHT 2013 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.
#

#assign port based on process id to allow concurrent publishing
let port=$$+1000
repo=alpha
pkg_path="`pwd`/../i386/repo"

if [ ! -z "$1" ]; then
	repo=$1
fi

#
# Start the pkg.depotd on local host
#
/usr/lib/pkg.depotd -d $pkg_path -p $port --readonly >/dev/null 2>&1 &
pid=$!
sleep 1

ssh -R $port:127.0.0.1:$port update@update-internal updaterepo.sh \
	-u http://localhost:$port/ $repo pluribusnetworks.com
status=$?

kill $pid

exit $status
