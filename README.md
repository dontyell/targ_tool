usage: targs.py [-h] -t TARGETS [-n NOSTRIKE] [-o OUTPUT] [-v]

This script will create a targets list based on the provided IP addresses or subnets.  
If provided, it will also remove no-strike IP addresses or subnets.  Output will be to stdout, 
or optionally, to a provided file.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --target TARGETS
                        target IP address or network (using CIDR or subnet mask), multiple allowed
  -n NOSTRIKE, --nostrike NOSTRIKE
                        no-strike IP address or network, multiple allowed
  -o OUTPUT, --output OUTPUT
                        file to write targets list to
  -v, --verbose

Examples:
        targs.py -t 192.168.1.0/24 -n 192.168.1.10 -o targs.txt
        targs.py -t 192.168.1.0/255.255.255.0 -n 192.168.1.0/29 -o targs.txt
        targs.py -t 10.0.1.0/24 -t 10.0.2.0/24 -t 10.0.3.0/24 -n 10.0.2.12 -n 10.0.3.3 -n 10.0.5.25
