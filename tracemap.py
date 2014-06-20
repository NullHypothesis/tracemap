#!/usr/bin/env python

import argparse

import netaddr
from scapy.all import *

MAX_TRACEROUTES = 100

def parse_cmd_args():
    """
    Parse the given command line arguments.
    """

    parser = argparse.ArgumentParser(description = "Run and visualise "
                                                   "traceroutes.")

    parser.add_argument("destinations",
                        type = str,
                        nargs = "+",
                        help = "Traceroute destinations.  Can be single "
                               "addresses or netblocks, e.g., 1.2.3.4/24.")

    parser.add_argument("-o",
                        "--output",
                        type = str,
                        default = "/tmp/traceroute.pdf",
                        help = "File where output is written to "
                               "(default: /tmp/traceroute.pdf).")

    parser.add_argument("-m",
                        "--maxttl",
                        type = int,
                        default = 20,
                        help = "Maximum TTL for traceroutes (default: 20).")

    parser.add_argument("-s",
                        "--sampling-rate",
                        type = int,
                        default = 1,
                        help = "Sampling rate for netblocks.  The given "
                               "number n means that one out of n IP addresses "
                               "is sampled (default: no sampling).")

    parser.add_argument("-r",
                        "--reckless",
                        action = "store_true",
                        help = "Must be used when running more than %d "
                               "traceroutes." % MAX_TRACEROUTES)

    return parser.parse_args()

def generate_destinations(aggregates, sampling_rate):
    """
    Turn netblocks into single destination IP addresses.
    """

    addresses = []

    for aggregate in [netaddr.IPSet([x]) for x in aggregates]:

        counter = 0

        for address in aggregate:
            if counter == 0:
                addresses.append(address)
            counter = (counter + 1) % sampling_rate

    return addresses

def main():
    """
    Entry point for this tool.
    """

    args = parse_cmd_args()

    destinations = map(str, generate_destinations(args.destinations,
                                                  args.sampling_rate))

    if (not args.reckless) and (len(destinations) > MAX_TRACEROUTES):
        print >> sys.stderr, \
                 "You need to be reckless to run more than %d traceroutes " \
                 "(%d given).  Use the command line switch `-r'." % \
                 (MAX_TRACEROUTES, len(destinations))
        return 1

    res, unans = traceroute(destinations, maxttl = args.maxttl)

    res.graph(type = "pdf", target = "> %s" % args.output)

if __name__ == "__main__":
    exit(main())
