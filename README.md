# tcpRapid
Fast enumeration and vulnerabilities scan with nmap

# Author 
@SantiLendakari

# Date
October 2019

# Description
Python3 fast enumeration and vulnerabilities scan with nmap
Launches a fast and silent enumeration scanner (nmap -sS). The next scanners are performed only on the hosts and ports founds active or open by the first scan.

# Requirements
```bash 
python3
python3-setuptools
python3-pip
nmap
```

```bash 
sudo pip install -r requirements.txt
```
or 
```bash 
sudo pip install python-nmap
sudo pip install termcolor
```
                        
# Usage
```bash
usage: sudo tcpRapid.py [-h] -t IP/Range [-p y/n] [-e y/n] [-v y/n]
                      [-o sSV/O]

Enumeration and vulnerabilities Scan. Execute with root privileges

optional arguments:
  -h, --help            show this help message and exit
  -t IP/URL, --target IP/URL
                        Target: IP or range
  -p y/n, --allPorts y/n
                        Scan all portos -slow-. Default 'n'
  -e y/n, --enumerationOnly y/n
                        Only show service enumeration. Not vulnerabilities.
                        Default 'n'
  -v y/n, --verbose y/n
                        Show info about NOT VURNERABLE items in vulnerability
                        scan. Default 'n'
  -o sSV, O. Default 'sSV', --enumerationOptions sSV, O. Default 'sSV'
                        Scan options

```

# Examples
```bash
$ sudo tcpRapid.py -t 192.168.0.0/24
```
```bash
$ sudo tcpRapid.py -p y -e y -v y -o O -t 192.168.0.2 
```
