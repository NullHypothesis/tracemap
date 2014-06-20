#!/usr/bin/env python

import argparse

from scapy.all import *

def parse_cmd_args():
    """
    Parse the given command line arguments.
    """

    parser = argparse.ArgumentParser(description = "Run and visualise "
                                                   "traceroutes.")

    parser.add_argument("destination",
                        type = str,
                        nargs = "+",
                        help = "Traceroute destinations.")

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

    return parser.parse_args()

def main():
    """
    Entry point for this tool.
    """

    args = parse_cmd_args()

    res, unans = traceroute(args.destination, maxttl = args.maxttl)

    res.graph(type = "pdf", target = "> %s" % args.output)

if __name__ == "__main__":
    exit(main())
