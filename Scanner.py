#!/usr/bin/python3
"""
Name: Parker Frame
Date: 2/7/2020 
Description: This tool is used for some basic level scanning bu utlizing scapy and nmap python libraries. """

#imported the nmap library
import nmap
import time
from scapy.all import *
import fpdf

#store scanner tool, nmap version, tgt
scanner = nmap.PortScanner()
nmapVer = scanner.nmap_version()

#prep the pdf formation
pdf = fpdf.FPDF(format='letter')
pdf.add_page()
pdf.set_font("Arial", size=10)

print("Welcome to the best scanner on this side of the Mississippi! Please use this tool wisely and ethically or else Professor Miller will be upset.")
print('\n')
print("<--------------------------------------------------------->")
time.sleep(1)
print('\n')

#options for the user to choose from
userResponse = input("""\nPlease enter the type of scan you want to run: (All options except #4 can save results to PDF!)
                        1)SYN/ACK Scan (TCP)
                        2)UDP Scan 
                        3)Ping Scan (ICMP)
                        4)Tracerroute
                        5)Comprehensive Scan (OS, Service, etc.) \n\n Choose from the above options (1-5) and press enter: """)
print("You have selected option: ", userResponse, " \n")

#start with tracerroute because its the simplest
if userResponse == '4':
    from scapy.all import *
    hostname = input("What domain or IP do you want to trace? (Ex. www.google.com, 192.168.1.153, etc.): ")
    print("This might take a bit so just sit back and relax while we trace the route!")
    print("If the trace gets stuck for too long then press Ctrl+C to end the trace.")
    print("<--------------------------------------------------------->")
    for i in range(1, 28):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        # Send the packet and get a reply
        reply = sr1(pkt, verbose=0)
        if reply is None:
            # No reply =(
            break
        elif reply.type == 3:
            # We've reached our destination
            print("Done!", reply.src)
            break
        else:
            # We're in the middle somewhere
            print("%d hops away: " % i , reply.src)
else:
    ipAddr = input("Enter the target IP address you want to scan (Ex. 192.168.1.1, 192.168.1.0/24, 192.168.1-30.230-250, etc.): ")
    print("The IP address you entered is: ", ipAddr)
    type(ipAddr)
    print('\n')
    tgtPorts = input("Enter the port range you want to scan, if applicable (Ex. 22, 80-95, 1-1000, etc.): ")
    print("The port range you entered is: ", tgtPorts)
    type(tgtPorts)


    print("This might take a bit so just sit back and relax while we scan away!")
    print("<--------------------------------------------------------->")
    #the other options are here
    if userResponse == '1':
        print("Nmap version: ",nmapVer[0],".",nmapVer[1])
        scanner.scan(ipAddr, tgtPorts, '-v -sS')
        # print(scanner.scaninfo())
        # print("IP Status: ", scanner[ipAddr].state())
        # print(scanner[ipAddr].all_protocols())
        # print("Open ports: ", scanner[ipAddr]['tcp'].keys())
        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, scanner[host].hostname()))
            print('State : %s' % scanner[host].state())
            for proto in scanner[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = scanner[host][proto].keys()
                for port in lport:
                    print ('port: %s\tstate: %s\tname: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
        #store data for pdf creation
        pdfData = scanner.csv()
        time.sleep(2)
        # print(pdfData)
    elif userResponse == '2':
        print("Nmap version: ",nmapVer[0],".",nmapVer[1])
        scanner.scan(ipAddr, tgtPorts, '-v -sU')
        # print(scanner.scaninfo())
        # print("IP Status: ", scanner[ipAddr].state())
        # print(scanner[ipAddr].all_protocols())
        # print("Open ports: ", scanner[ipAddr]['udp'].keys())
        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, scanner[host].hostname()))
            print('State : %s' % scanner[host].state())
            for proto in scanner[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = scanner[host][proto].keys()
                for port in lport:
                    print ('port: %s\tstate: %s\tname: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
        pdfData = scanner.csv()
        time.sleep(2)
    elif userResponse == '3':
        print("Nmap version: ",nmapVer[0],".",nmapVer[1])
        scanner.scan(ipAddr, tgtPorts, '-v -PE')
        # print(scanner.scaninfo())
        # print(scanner.csv())
        # print("IP Status: ", scanner[ipAddr].state())
        # print(scanner[ipAddr].all_protocols())
        # print("Open ports: ", scanner[ipAddr]['tcp'].keys())
        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, scanner[host].hostname()))
            print('State : %s' % scanner[host].state())
            for proto in scanner[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = scanner[host][proto].keys()
                for port in lport:
                    print ('port: %s\tstate: %s\tname: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
        pdfData = scanner.csv()
        time.sleep(2)
    elif userResponse == '5':
        print("Nmap version: ",nmapVer[0],".",nmapVer[1])
        scanner.scan(ipAddr, tgtPorts, '-v -sS -sV -sC -A -O')
        # print(scanner.scaninfo())
        # print("IP Status: ", scanner[ipAddr].state())
        # print(scanner[ipAddr].all_protocols())
        # print("Open ports: ", scanner[ipAddr]['tcp'].keys())
        for host in scanner.all_hosts():
            print('----------------------------------------------------')
            print('Host : %s (%s)' % (host, scanner[host].hostname()))
            print('State : %s' % scanner[host].state())
            for proto in scanner[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
                lport = scanner[host][proto].keys()
                for port in lport:
                    print ('port: %s\tstate: %s\tname: %s' % (port, scanner[host][proto][port]['state'], scanner[host][proto][port]['name']))
        pdfData = scanner.csv()
        time.sleep(2)
    elif userResponse >= '6':
        print("Please enter a valid option")
time.sleep(2)
print("<--------------------------------------------------------->")
print("Your scan is complete!")
pdfInput = input("\nDo you want to store the csv of your results in a python-generated pdf? It's prettty coool....""""
                        1) Yes, I am awesome and I want to do that!
                        2) No, I don't want to do that cool thing. \n\n Choose from the above options and press enter: """)
#loop through data and generate pdf
if pdfInput == '1':
    for i in pdfData:
        pdf.write(5,str(i))
    pdf.output("scanResults.pdf")
elif pdfInput == '2':
    print("You missed out man...I'm sorry")