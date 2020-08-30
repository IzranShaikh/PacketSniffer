# PacketSniffer
An Easy to Use CLI Packet Sniffer that sniffs hosts,urls,raw loads - form data,credentials and Display them in Descriptive way(made in Python2 for Linux Platforms : Kali Linux Preferred)


How To Use:

1.Install modules stated in requirements.txt for python2
2.Run the script using python2 and pass in the network interface you want to sniff (ether or wlan to get the name of your available interface use ifconfig)

Sniffing will be started any requests send by any client on your network will be displayed along with thier ip, url they sent req on and even credentials they enter on forms.

The credential details can't be extracted from ssl secured websites
For that you need to perform a mitm on your target and pair it with sslstrip(available on kali linux) then execute this packet sniffer.


How it Works:
It takes the network interface as an input and starts sniffing on those interfaces.
Any requests packet sent from your network will be captured and analyzed for useful details such as sender's ip, recv's ip,requested url and even form data.
Those details then are displayed on the interface.
