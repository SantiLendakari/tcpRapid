# !/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                        tcpRapid1.0 - Enumeration and vulnerabilities scan
                        Version 1.0
                        Author - Santiago Rodríguez González
                        Date - October 2019

                        Description - Launches a fast and silent enumeration scanner (nmap -sS). The next scanners
                        are performed only on the hosts and ports founds active or open by the first scan.
                        Enumeration and vulnerabilities scan with nmap.
                       
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import argparse
from termcolor import colored
import os, sys
from nmapFunctions import nmapPre

enumerationOptionsD = ["sSV","O"]
otionsyn = ["y","n"]

def desc(target, enumerationOnly ,enumerationOptions, allPorts, verbose):
    nmapPre(target, enumerationOptions, allPorts, verbose)

def main():
    parser = argparse.ArgumentParser(description="Enumeration and vulnerabilities Scan. Execute with root privileges")
    parser.add_argument("-t", "--target", dest="target", type=str,help="Target: IP or range", metavar="IP/URL")
    parser.add_argument("-p", "--allPorts", dest="allPorts", type=str,help="Scan all portos -slow-. Default 'n'", metavar="y/n", default='n')
    parser.add_argument("-e", "--enumerationOnly", dest="enumerationOnly", type=str,help="Only show service enumeration. Not vulnerabilities. Default 'n'", metavar="y/n", default='n')
    parser.add_argument("-v", "--verbose", dest="verbose", type=str,help="Show info about NOT VURNERABLE items in vulnerability scan. Default 'n'", metavar="y/n", default='n')
    parser.add_argument("-o", "--enumerationOptions", dest="enumerationOptions", type=str,help="Scan options", metavar="sSV, O. Default 'sSV'", default='sSV')

    args = parser.parse_args()
    if (args.target) and (args.enumerationOptions in enumerationOptionsD) and (args.allPorts in otionsyn) and (args.enumerationOnly in otionsyn) and (args.verbose in otionsyn):
        if (args.enumerationOnly == "n"):
            args.enumerationOptions = args.enumerationOptions + " --script=vuln"
        desc(args.target, args.enumerationOnly, args.enumerationOptions, args.allPorts, args.verbose)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
