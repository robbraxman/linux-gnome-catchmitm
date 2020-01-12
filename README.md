# linux-gnome-catchmitm
(C) Copyright Braxmobile Inc 2020 - GPL V3 License - Free Software

The purpose of this app is for network intrusion detection. It can identify all 
devices on your subnet. It tracks all unique DNS calls. You are able to check
if any of the https certificates are spoofed. You can do a basic port scan
to identify the type of device discovered on the network. You can add a 
manual description/label to a device which will be stored in its database
for future reference (by MAC address). Then if you wish to interrupt some
unknown device, you can jam the identified device.

Limitations: This only works on your current subnet. By default, it is
designed to be used in wireless (wifi mode) though that can be altered
easily in the code. Listed devices do not get removed if you change your
network. For best results, restart the app when you change networks.

UI: the UI is currently GTK+ 3 for Gnome. It is sized for a smartphone so
in theory it should be sized for a Linux phone like a Librem 5. Because it 
is a GTK app, it will not run well on Ubuntu Touch. Will work on a QT version.

How to Use: To use the app, just start the network monitoring and just leave 
it alone. It will start passively observing the network and will start to 
build data. Then you can go to each tab and examine the activity with devices, 
and DNS. An example use is to let it run when you're not using the device 
(like when going to sleep). This can detect if malware is communicating in
the background. It also reveals OS telemetry that is going in.

This is an alpha stage dev project. Still lots of cleanup to do. 
Next step is to integrate with Libhandy and 
a QT version.

FOR UBUNTU 18.04

For Dev Environment:

sudo snap install pycharm-community --classic

sudo apt-get install python3-pip


To Install:

Copy all the files to your desired directory (e.g. ~/Documents/catchmitm).

Install the required Python modules.

sudo apt-get install python3-scapy

sudo pip3 install dnspython

sudo pip3 install psutil



To run, go to that directory and run

./start.sh




