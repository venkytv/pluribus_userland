#!/usr/bin/python
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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

"""feed - routines for generating RFC 4287 Atom feeds for packaging server

   At present, the pkg.server.feed module provides a set of routines that, from
   a catalog, allow the construction of a feed representing the activity within
   a given time period."""

import cherrypy
from cherrypy.lib.static import serve_file
import copy
import cStringIO
import datetime
import httplib
import os
import rfc822
import time
import urllib
import urlparse
import uuid
import xml.dom.minidom as xmini

from pkg.misc import get_rel_path
import pkg.catalog as catalog

MIME_TYPE = "application/atom+xml"
CACHE_FILENAME = "feed.xml"
RFC3339_FMT = "%Y-%m-%dT%H:%M:%SZ"

def dt_to_rfc3339_str(ts):
        """Returns a string representing a datetime object formatted according
        to RFC 3339.
        """
        return ts.strftime(RFC3339_FMT)

def rfc3339_str_to_dt(ts_str):
        """Returns a datetime object representing 'ts_str', which should be in
        the format specified by RFC 3339.
        """
        return datetime.datetime(*time.strptime(ts_str, RFC3339_FMT)[0:6])

def fmri_to_taguri(f):
        """Generates a 'tag' uri compliant with RFC 4151.  Visit
        http://www.taguri.org/ for more information.
        """
        return "tag:%s,%s:%s" % (f.publisher,
            f.get_timestamp().strftime("%Y-%m-%d"),
            urllib.unquote(f.get_url_path()))

def init(depot):
        """This function performs general initialization work that is needed
        for feeds to work correctly.
        """

        repo = depot.repo
        if repo.feed_cache_root and not \
            (repo.read_only and not repo.writable_root):
                # Ensure any configuration changes are reflected in the feed.
                __clear_cache(repo)

def set_title(depot, doc, feed, update_ts):
        """This function attaches the necessary RSS/Atom feed elements needed
        to provide title, author and contact information to the provided
        xmini document object using the provided feed object and update
        time.
        """

        t = doc.createElement("title")
        ti = xmini.Text()
        ti.replaceWholeText(depot.cfg.get_property("pkg_bui", "feed_name"))
        t.appendChild(ti)
        feed.appendChild(t)

        l = doc.createElement("link")
        l.setAttribute("href", cherrypy.url())
        l.setAttribute("rel", "self")
        feed.appendChild(l)

        # Atom requires each feed to have a permanent, universally unique
        # identifier.
        i = doc.createElement("id")
        it = xmini.Text()
        netloc, path = urlparse.urlparse(cherrypy.url())[1:3]
        netloc = netloc.split(":", 1)[0]
        tag = "tag:%s,%s:%s" % (netloc, update_ts.strftime("%Y-%m-%d"), path) 
        it.replaceWholeText(tag)
        i.appendChild(it)
        feed.appendChild(i)

        # Indicate when the feed was last updated.
        u = doc.createElement("updated")
        ut = xmini.Text()
        ut.replaceWholeText(dt_to_rfc3339_str(update_ts))
        u.appendChild(ut)
        feed.appendChild(u)

        # Add our icon.
        i = doc.createElement("icon")
        it = xmini.Text()
        it.replaceWholeText(depot.cfg.get_property("pkg_bui", "feed_icon"))
        i.appendChild(it)
        feed.appendChild(i)

        # Add our logo.
        l = doc.createElement("logo")
        lt = xmini.Text()
        lt.replaceWholeText(depot.cfg.get_property("pkg_bui", "feed_logo"))
        l.appendChild(lt)
        feed.appendChild(l)

        maintainer = depot.repo.cfg.get_property("repository", "maintainer")
        # The author information isn't required, but can be useful.
        if maintainer:
                name, email = rfc822.AddressList(maintainer).addresslist[0]

                if email and not name:
                        # If we got an email address, but no name, then
                        # the name was likely parsed as a local address. In
                        # that case, assume the whole string is the name.
                        name = maintainer
                        email = None

                a = doc.createElement("author")

                # First we have to add a name element. This is required if an
                # author element exists.
                n = doc.createElement("name")
                nt = xmini.Text()
                nt.replaceWholeText(name)
                n.appendChild(nt)
                a.appendChild(n)

                if email:
                        # If we were able to extract an email address from the
                        # maintainer information, add the optional email
                        # element to provide a point of communication.
                        e = doc.createElement("email")
                        et = xmini.Text()
                        et.replaceWholeText(email)
                        e.appendChild(et)
                        a.appendChild(e)

                # Done with the author.
                feed.appendChild(a)

add_op = ("Added", "%s was added to the repository.")
remove_op = ("Removed", "%s was removed from the repository.")
update_op = ("Updated", "%s, a new version of an existing package, was added "
    "to the repository.")

def add_transaction(request, doc, feed, entry, first):
        """Each transaction is an entry.  We have non-trivial content, so we
        can omit summary elements.
        """

        e = doc.createElement("entry")

        pfmri, op_type, op_time, metadata = entry
 
        # Generate a 'tag' uri, to uniquely identify the entry, using the fmri.
        i = xmini.Text()
        i.replaceWholeText(fmri_to_taguri(pfmri))
        eid = doc.createElement("id")
        eid.appendChild(i)
        e.appendChild(eid)

        # Attempt to determine the operation that was performed and generate
        # the entry title and content.
        if op_type == catalog.CatalogUpdate.ADD:
                if pfmri != first:
                        # XXX renaming, obsoletion?
                        # If this fmri is not the same as the oldest one
                        # for the FMRI's package stem, assume this is a
                        # newer version of that package.
                        op_title, op_content = update_op
                else:
                        op_title, op_content = add_op
        elif op_type == catalog.CatalogUpdate.REMOVE:
                op_title, op_content = add_op
        else:
                # XXX Better way to reflect an error?  (Aborting will make a
                # non-well-formed document.)
                op_title = "Unknown Operation"
                op_content = "%s was changed in the repository."

        # Now add a title for our entry.
        etitle = doc.createElement("title")
        ti = xmini.Text()
        ti.replaceWholeText(" ".join([op_title, pfmri.get_pkg_stem()]))
        etitle.appendChild(ti)
        e.appendChild(etitle)

        # Indicate when the entry was last updated (in this case, when the
        # package was added).
        eu = doc.createElement("updated")
        ut = xmini.Text()
        ut.replaceWholeText(dt_to_rfc3339_str(op_time))
        eu.appendChild(ut)
        e.appendChild(eu)

        # Link to the info output for the given package FMRI.
        e_uri = get_rel_path(request, "info/0/%s" % urllib.quote(str(pfmri)))

        l = doc.createElement("link")
        l.setAttribute("rel", "alternate")
        l.setAttribute("href", e_uri)
        e.appendChild(l)

        # Using the description for the operation performed, add the FMRI and
        # tag information.
        content_text = op_content % pfmri

        co = xmini.Text()
        co.replaceWholeText(content_text)
        ec = doc.createElement("content")
        ec.appendChild(co)
        e.appendChild(ec)

        feed.appendChild(e)

def get_updates_needed(repo, ts):
        """Returns a list of the CatalogUpdate files that contain the changes
        that have been made to the catalog since the specified UTC datetime
        object 'ts'."""

        c = repo.catalog
        if c.last_modified <= ts:
                # No updates needed.
                return []

        updates = set()
        for name, mdata in c.updates.iteritems():

                # The last component of the update name is the locale.
                locale = name.split(".", 2)[2]

                # For now, only look at CatalogUpdates that for the 'C'
                # locale.  Any other CatalogUpdates just contain localized
                # catalog data, so aren't currently interesting.
                if locale != "C":
                        continue

                ulog_lm = mdata["last-modified"]
                if ulog_lm <= ts:
                        # CatalogUpdate hasn't changed since 'ts'.
                        continue
                updates.add(name)

        if not updates: 
                # No updates needed.
                return []

        # Ensure updates are in chronological ascending order.
        return sorted(updates)

def update(request, depot, last, cf):
        """Generate new Atom document for current updates.  The cached feed
        file is written to repo.feed_cache_root/CACHE_FILENAME.
        """

        # Our configuration is stored in hours, convert it to days and seconds.
        hours = depot.cfg.get_property("pkg_bui", "feed_window")
        days, hours = divmod(hours, 24)
        seconds = hours * 60 * 60
        feed_ts = last - datetime.timedelta(days=days, seconds=seconds)

        d = xmini.Document()

        feed = d.createElementNS("http://www.w3.org/2005/Atom", "feed")
        feed.setAttribute("xmlns", "http://www.w3.org/2005/Atom")

        set_title(depot, d, feed, depot.repo.catalog.last_modified)

        d.appendChild(feed)

        # Cache the first entry in the catalog for any given package stem found
        # in the list of updates so that it can be used to quickly determine if
        # the fmri in the update is a 'new' package or an update to an existing
        # package.
        c = depot.repo.catalog

        first = {}
        def get_first(f):
                stem = f.get_pkg_stem()
                if stem in first:
                        return first[stem]

                for v, entries in c.entries_by_version(f.pkg_name):
                        # The first version returned is the oldest version.
                        # Add all of the unique package stems for that version
                        # to the list.
                        for efmri, edata in entries:
                                first[efmri.get_pkg_stem()] = efmri
                        break

                if stem not in first:
                        # A value of None is used to denote that no previous
                        # version exists for this particular stem.  This could
                        # happen when a prior version exists for a different
                        # publisher, or no prior version exists at all.
                        first[stem] = None
                return first[stem]

        # Updates should be presented in reverse chronological order.
        for name in reversed(get_updates_needed(depot.repo, feed_ts)):
                ulog = catalog.CatalogUpdate(name, meta_root=c.meta_root)
                for entry in ulog.updates():
                        pfmri = entry[0]
                        op_time = entry[2]
                        if op_time <= feed_ts:
                                # Exclude this particular update.
                                continue
                        add_transaction(request, d, feed, entry,
                            get_first(pfmri))

        d.writexml(cf)

def __get_cache_pathname(repo):
        return os.path.join(repo.feed_cache_root, CACHE_FILENAME)

def __clear_cache(repo):
        if repo.read_only and repo.writable_root:
                # Ignore the request due to repository configuration.
                return

        pathname = __get_cache_pathname(repo)
        try:
                if os.path.exists(pathname):
                        os.remove(pathname)
        except IOError:
                raise cherrypy.HTTPError(
                    httplib.INTERNAL_SERVER_ERROR,
                    "Unable to clear feed cache.")

def __cache_needs_update(repo):
        """Checks to see if the feed cache file exists and if it is still
        valid.  Returns False, None if the cache is valid or True, last
        where last is a timestamp representing when the cache was
        generated.
        """
        cfpath = __get_cache_pathname(repo)
        last = None
        need_update = True
        if os.path.isfile(cfpath):
                # Attempt to parse the cached copy.  If we can't, for any
                # reason, assume we need to remove it and start over.
                try:
                        d = xmini.parse(cfpath)
                except Exception:
                        d = None
                        __clear_cache(repo)

                # Get the feed element and attempt to get the time we last
                # generated the feed to determine whether we need to regenerate
                # it.  If for some reason we can't get that information, assume
                # the cache is invalid, clear it, and force regeneration.
                fe = None
                if d:
                        fe = d.childNodes[0]

                if fe:
                        utn = None
                        for cnode in fe.childNodes:
                                if cnode.nodeName == "updated":
                                        utn = cnode.childNodes[0]
                                        break

                        if utn:
                                last = rfc3339_str_to_dt(utn.nodeValue.strip())

                                # Since our feed cache and updatelog might have
                                # been created within the same second, we need
                                # to ignore small variances when determining
                                # whether to update the feed cache.
                                up_ts = copy.copy(repo.catalog.last_modified)
                                up_ts = up_ts.replace(microsecond=0)
                                if last >= up_ts:
                                        need_update = False
                        else:
                                __clear_cache(repo)
                else:
                        __clear_cache(repo)
        return need_update, last

def handle(depot, request, response):
        """If there have been package updates since we last generated the feed,
        update the feed and send it to the client.  Otherwise, send them the
        cached copy if it is available.
        """

        repo = depot.repo
        cfpath = __get_cache_pathname(repo)

        # First check to see if we already have a valid cache of the feed.
        need_update, last = __cache_needs_update(repo)

        if need_update:
                # Update always looks at feed.window seconds before the last
                # update until "now."  If last is none, we want it to use "now"
                # as its starting point.
                if last is None:
                        last = datetime.datetime.utcnow()

                if repo.read_only and not repo.writable_root:
                        # If the server is operating in readonly mode, the
                        # feed will have to be generated every time.
                        cf = cStringIO.StringIO()
                        update(request, depot, last, cf)
                        cf.seek(0)
                        buf = cf.read()
                        cf.close()

                        # Now that the feed has been generated, set the headers
                        # correctly and return it.
                        response.headers['Content-type'] = MIME_TYPE

                        # Return the current time and date in GMT.
                        response.headers['Last-Modified'] = rfc822.formatdate()

                        response.headers['Content-length'] = len(buf)
                        return buf
                else:
                        # If the server isn't operating in readonly mode, the
                        # feed can be generated and cached in inst_dir.
                        cf = file(cfpath, "w")
                        update(request, depot, last, cf)
                        cf.close()

        return serve_file(cfpath, MIME_TYPE)
