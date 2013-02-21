#!/usr/bin/python

# Licensing:
# Copyright (c) 2012 Team Search Operations
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE. 

from optparse import OptionParser
import pprint
import sys
import requests
from lxml import etree

def setup(parser):
    '''setting up the commandline argument parser'''
    parser.add_option("-v", "--verbose", dest="verbose",\
            help="make some verbose output for testing", action="store_true")
    parser.add_option("-H", "--host", dest="host", help="the host to check")
    parser.add_option("-p", "--port", dest="port", help="port to check",\
            type="int")
    parser.add_option("-u", "--url", dest="url", help="url to check")
    parser.add_option("-w", "--warning", dest="warn",\
            help="if result of boolean(XPATH) is true, i.e. the item is found," + \
            " the service enters a warning state", metavar="XPATH")
    parser.add_option("-c", "--critical", dest="crit",\
            help="if result of boolean(XPATH) is true, i.e. the item is found," + \
            " the service enters a critical state", metavar="XPATH")
    parser.add_option("-a", "--attribute", dest="attr",\
            help="output string(XPATH) as performancedata", metavar="XPATH") 
    parser.add_option("-e", "--evil", dest="evil",\
            help="do not validate the input xml document", action="store_true")
    parser.add_option("-s", "--ssl", dest="ssl", help="use ssl connection",\
            action="store_true")
    return(parser.parse_args())


def getPort(prt, ssl):
    '''utility function to map from ssl flag or port variable to correct port.'''
    if prt == None:
        if ssl:
            port = 443
        else:
            port = 80
    else:
        port = prt
    return port


def main():
    '''main function running the check'''
    parser = OptionParser("%prog -H HOST -u URL [-p PORT] " + \
            "(-w WARNING |-c CRITICAL) [-s] [-e]")
    (opts, args) = setup(parser)
    if opts.host == None or opts.url == None or \
            (opts.warn == None and opts.crit == None and opts.attr == None):
        parser.print_help()
        sys.exit(3)
    try:
        fullUrl = "https://" if opts.ssl else "http://" + opts.host + ":" + \
                str(getPort(opts.port, opts.ssl)) + opts.url
        if opts.verbose:
            print "fetching " + fullUrl
        xml = requests.get(fullUrl, headers={"User-Agent": "nagios"}).content
        if opts.evil:
            parsed = etree.HTML(xml)
        else:
            parsed = etree.XML(xml)
        if opts.verbose:
            print etree.tostring(parsed)
        if opts.warn:
            warn = parsed.xpath(opts.warn)
        else:
            warn = False
        if opts.crit:
            crit = parsed.xpath(opts.crit)
        else:
            crit = False

        rv = [0, "OK - did not find " + ("" if opts.warn == None else opts.warn) \
                + (" and " if opts.warn and opts.crit else "") + \
                ("" if opts.crit == None else opts.crit)]
        if warn:
            rv = [1, "WARN - did find warning xpath " + opts.warn]
        if crit:
            rv = [2, "CRIT - did find critical xpath " + opts.crit]

        if opts.attr:
            attrv = str(parsed.xpath(opts.attr))
            if rv[0]:
                rv[1] += ". value found was {0}".format(attrv)
            rv[1] += "|attr=" + attrv

        print rv[1]
        sys.exit(rv[0])
    except Exception as e:
        print "EXCEPTION:", e
        import traceback
        traceback.print_exc()
        print "url to fetch:   ", "https://" if opts.ssl else "http://" + \
                opts.host + ":" + str(getPort(opts.port, opts.ssl)) + opts.url
        print "warning xpath:  ", opts.warn
        print "critical xpath: ", opts.crit
        print "attrib xpath:   ", opts.attr
        sys.exit(3)

if __name__ == "__main__":
    main()  
