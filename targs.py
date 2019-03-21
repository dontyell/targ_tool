#!/usr/bin/env python3

# Create capability to replace existing methods to create targets list
# Requirements:
# 1) must run from the command line - CHECK
# 2) must accept multiple target subnets - CHECK
# 3) must accept cidr notation and subnet - CHECK
# 4) must have a help functionality - CHECK
# 5) must not have external dependencies - CHECK
# 6) you must be willing and able brief tool description and functionality in 3 minutes - WON'T BE HERE

# No current requirement to remove no strikes but that could be a winning feature... - CHECK

import ipaddress
import sys
import logging
import argparse
from argparse import RawTextHelpFormatter
from pathlib import Path

class CustomConsoleFormatter(logging.Formatter):
    err_fmt  = "ERROR: %(msg)s"
    dbg_fmt  = "DEBUG: %(module)s: %(lineno)d: %(msg)s"
    info_fmt = "%(msg)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')  

    def format(self, record):

        # Save the original format configured by the user
        # when the logger formatter was instantiated
        format_orig = self._style._fmt

        # Replace the original format with one customized by logging level
        if record.levelno == logging.DEBUG:
            self._style._fmt = CustomConsoleFormatter.dbg_fmt

        elif record.levelno == logging.INFO:
            self._style._fmt = CustomConsoleFormatter.info_fmt

        elif record.levelno == logging.ERROR:
            self._style._fmt = CustomConsoleFormatter.err_fmt

        # Call the original formatter class to do the grunt work
        result = logging.Formatter.format(self, record)

        # Restore the original format configured by the user
        self._style._fmt = format_orig

        return result

def getinfo_options():
        epilog_str = '''Examples:
        %(prog)s -t 192.168.1.0/24 -n 192.168.1.10 -o targs.txt
        %(prog)s -t 192.168.1.0/255.255.255.0 -n 192.168.1.0/29 -o targs.txt
        %(prog)s -t 10.0.1.0/24 -t 10.0.2.0/24 -t 10.0.3.0/24 -n 10.0.2.12 -n 10.0.3.3 -n 10.0.5.25'''

        description_str = '''This script will create a targets list based on the provided IP addresses or subnets.  
If provided, it will also remove no-strike IP addresses or subnets.  Output will be to stdout, 
or optionally, to a provided file.'''

        opts = argparse.ArgumentParser(description=description_str, epilog=epilog_str, 
                                         formatter_class=RawTextHelpFormatter)
                                         
        opts.add_argument('-t', '--target', dest='targets', action='append', required=True, help='target IP address or network (using CIDR or subnet mask), multiple allowed', default=None)
        opts.add_argument('-n', '--nostrike', dest='nostrike', action='append', help='no-strike IP address or network, multiple allowed', default=None)
        opts.add_argument('-o', '--output', dest='output', help='file to write targets list to')
        opts.add_argument('-v', '--verbose', action='count')
        return opts
        
def is_address(addr):
    try:
        ip = ipaddress.ip_address(addr)
        logger.debug('%s is a proper IP%s address.' % (ip, ip.version))
        return True
    except ValueError:
        logger.debug('%s is not a proper IP address' % addr)
        return False

def is_subnet(subnet):
    try:
        ip = ipaddress.ip_network(subnet)
        logger.debug('%s is a proper cidr/netmask format' % ip)
        return True
    except ValueError:
        logger.debug('address/netmask is invalid: %s' % subnet)
        return False

def write_file(targ_set, nsl_set, outfile):
    targ_output = open(outfile, 'w')
    for item in sorted(targ_set.difference(nsl_set)):
        targ_output.write(str(item) + "\n")
    targ_output.close()
    logger.info("Your target list can be found in {}".format(outfile))

def main(options):
    if options.verbose:
        logger.info("Verbose output on, level: {}".format(options.verbose))
        logger.setLevel(logging.DEBUG)

    logger.info("Building targets list...")
    # targ_list = []
    targ_set = set()
    for targ in options.targets:
        if is_address(targ):
            # targ_list.append(targ)
            targ_set.add(ipaddress.ip_address(targ))
        elif is_subnet(targ):
            targets = ipaddress.ip_network(targ)
            # targ_list.extend(list(targets))
            targ_set.update(list(targets.hosts()))
        else:
            logger.error("%s is not a valid target" % targ)
    
    logger.info("Removing No-Strikes...")
    nsl_set = set()
    if options.nostrike:
        for nsl in options.nostrike:
            if is_address(nsl):
                try:
                    # targ_list.remove(ipaddress.ip_address(nsl))
                    nsl_set.add(ipaddress.ip_address(nsl))
                except ValueError:
                    logger.info("{} does not exist in target list, no need to remove".format(nsl))
            elif is_subnet(nsl):
                try:
                    for addr in ipaddress.ip_network(nsl).hosts():
                        # targ_list.remove(addr)
                        nsl_set.add(addr)
                        logger.debug("Removing {}".format(addr))

                except ValueError:
                    logger.info("{} does not exist in target list, no need to remove".format(nsl))
            else:
                logger.error("{} is not a valid IP address or subnet".format(nsl))
    
    if options.output:
        targ_output = Path(options.output)
        
        if targ_output.exists():
            if targ_output.is_file():
                overwrite = input('File already exists. Overwrite? Y = yes, N = no\n')
                if overwrite.lower() == 'y':
                    write_file(targ_set, nsl_set, options.output)
                else:
                    logger.error("Will not overwrite {}; exiting...".format(targ_output))
                    sys.exit()
            elif targ_output.is_dir():
                logger.error("{} is a directory; exiting...".format(targ_output))
                sys.exit()
        else:
            write_file(targ_set, nsl_set, options.output)
    else:
        logger.info("Targets List:")
        for item in sorted(targ_set.difference(nsl_set)):
            print(item)

if __name__ == "__main__":
    parser = getinfo_options()
    options = parser.parse_args()
    
    # create logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # create console handler and set level to info
    ch = logging.StreamHandler()
    
    # create formatter
    # formatter = logging.Formatter('%(message)s')
    formatter = CustomConsoleFormatter()

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    main(options)