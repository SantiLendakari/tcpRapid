#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

                                NMAP FUNCTIONS

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
import nmap
import time
from termcolor import colored

def nmapPre(ipE, enumerationOptions, puertosT, verbose):

    import nmap
    nm = nmap.PortScanner()
    ip = ipE
    opcion="sS"

    print ("Start time: " + time.strftime("%H:%M:%S") )

    if (puertosT=="n"):
        resultados=nm.scan(hosts=ip, arguments=opcion)
    else:
        puertosT = " -p-"
        resultados=nm.scan(hosts=ip, arguments=opcion+puertosT)

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            ports = str(list(nm[host][proto].keys()))[1:-1]
            ports.strip()
            nmapP(host, "-" + enumerationOptions + " -p ", ports.replace(" ", ""), verbose)

    print ("End time: " + time.strftime("%H:%M:%S") )


def nmapP(ipE, opcion, puertosE, verbose):

    nm = nmap.PortScanner()
    ip = ipE
    puertos = puertosE

    if (puertos=="n"):
        resultados=nm.scan(hosts=ip, arguments=opcion)
    else:
        resultados=nm.scan(hosts=ip, arguments=opcion+puertos)

    for host in nm.all_hosts():

        print('----------------------------------------------------')
        if (nm[host].state() == "up"):
            print('Host : %s (%s)' % (host, nm[host].hostname()) + " " + colored(str(nm[host].state()),'green',attrs=['bold', 'blink']))
        else:
            print('Host : %s (%s)' % (host, nm[host].hostname()) + " " + colored(str(nm[host].state()),'red',attrs=['bold', 'blink']))

        #print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            #lport.sort()
            for port in lport:
                if (str(nm[host][proto][port]['state']) == "open"):
                    print ("Port: " + str(port) + " " + colored(str(nm[host][proto][port]['state']),'green',attrs=['bold', 'blink']) + " " + str(nm[host][proto][port]['name'])+ " " + str(nm[host][proto][port]['product']) + " " + str(nm[host][proto][port]['extrainfo'])+ " " + str(nm[host][proto][port]['reason'])+ " " + str(nm[host][proto][port]['version'])+ " " + str(nm[host][proto][port]['conf'])+ " " + str(nm[host][proto][port]['cpe']))
                    # Options that use scripts it show content of nm[host][proto][port]['script']
                    if 'script' in nm[host][proto][port]:
                        for key in nm[host][proto][port]['script']:
                            if (str(nm[host][proto][port]['script'][key]).find("VULNERABLE"))>-1 and (str(nm[host][proto][port]['script'][key]).find("NOT VULNERABLE")==-1) :
                                print(colored(str(key),'red',attrs=['bold', 'blink']), '=>', nm[host][proto][port]['script'][key])
                            elif (verbose == "y"):
                                print(str(key), '=>', nm[host][proto][port]['script'][key])
                    #else:
                        #print ("Port: " + str(port) + " " + colored(str(nm[host][proto][port]['state']),'green',attrs=['bold', 'blink']) + " " + str(nm[host][proto][port]['name'])+ " " + str(nm[host][proto][port]['product']) + " " + str(nm[host][proto][port]['extrainfo'])+ " " + str(nm[host][proto][port]['reason'])+ " " + str(nm[host][proto][port]['version'])+ " " + str(nm[host][proto][port]['conf'])+ " " + str(nm[host][proto][port]['cpe']))
                else:
                    print ("Port: " + str(port) + " " + str(nm[host][proto][port]['state']) + " " + str(nm[host][proto][port]['name'])+ " " + str(nm[host][proto][port]['product']) + " " + str(nm[host][proto][port]['extrainfo'])+ " " + str(nm[host][proto][port]['reason'])+ " " + str(nm[host][proto][port]['version'])+ " " + str(nm[host][proto][port]['conf'])+ " " + str(nm[host][proto][port]['cpe']))
        ## SO informatio with option -O:
        if 'osmatch' in nm[host]:
            print("SO information: "+ "*Type:* " +  resultados['scan'][ip]['osmatch'][0]['osclass'][0]['type'] + " *Vendor:* " + resultados['scan'][ip]['osmatch'][0]['osclass'][0]['vendor'] + " *OS Family:* " + resultados['scan'][ip]['osmatch'][0]['osclass'][0]['osfamily'] + " *OSgen:* " + resultados['scan'][ip]['osmatch'][0]['osclass'][0]['osgen'] + " *Accuracy:* " + resultados['scan'][ip]['osmatch'][0]['osclass'][0]['accuracy'] )
        ## For scripts with this info:
        if 'hostscript' in nm[host]:
            print(str(nm[host]['hostscript']))
