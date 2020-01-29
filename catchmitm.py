import ssl
import socket
import hashlib
import io
import requests
import time
import pickle
from array import *
from scapy.config import conf

conf.ipv6_enabled = False
from scapy.all import *
import sys
from datetime import datetime
import threading
import dns.resolver
import psutil
import os
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gdk, GObject
#gi.require_version('Handy', '0.0')
#from gi.repository import Handy

class MainWindow(Gtk.Window):

    scapy = 0
    scapyJam = 0
    scapyPing = 0
    scapyScan = 0
    lastDomain = ''
    wlan = ""
    discovered_if = ''
    deviceList = {}
    vendorList = {}
    portList = {'22':'ssh','443':'https','80':'http','8080':'privateweb','53':'dns','143':'imap','465':'smtp/s','993':'imap/s','110':'pop3',
                '5353':'mdns','1900':'upnp','5900':'vnc','20':'ftp','25':'smtp','137':'netbios','161':'snmp'
               }
    deviceDescList = {}
    monitorLock = False
    sniffStatus = False
    jamStatus = False
    subnet = ""
    netmask = ""
    installDir = ""
    appdataDir = ""
    netDevice = ""                                                                                      
    portScanningStatus = False
    userlogin = ""

    def __init__(self):

        #os.system('clear')
        print('Starting Catch MITM')
        self.userlogin = os.getlogin()
        self.appdataDir = "/home/"+self.userlogin+"/.config/catchmitm"
        os.system("mkdir "+self.appdataDir)
        subprocess.call(["chmod","0755",self.appdataDir+"/wifi-device.conf"])
        subprocess.call(["chmod","0755",self.appdataDir+"/_devicelist.dict"])
        print("User File area ->"+self.appdataDir)


        try:
            self.deviceDescList = pickle.load(open(self.appdataDir+"/_devicelist.dict", "rb"))
        except Exception as e:
            print(e)
            print('No devicelist')

        self.ui_gtk_init()

        self.monitorLock = threading.Semaphore()
        self.discoverNetDevice()
        #---------------------------------------------------
        #os.system("sudo ifconfig "+self.netDevice+" promisc")
        #---------------------------------------------------

        #cleanupThread = threading.Thread(target=self.treeCleanup, )
        #cleanupThread.daemon = True
        #daemons get automatically closed when app exits
        #cleanupThread.start()


    def ui_gtk_init(self):
        #---------------------------------------------------
        # GTK+ 3 UI
        #---------------------------------------------------


        #---------------------------------------------------
        # Set Up Main Window
        #---------------------------------------------------
        Gtk.Window.__init__(self, title="Catch Man-in-the-Middle")
        self.set_size_request(400, 700)
        self.set_border_width(10)

        self.timeout_id = None
        self.set_icon_from_file("lock-orig.png")

        #---------------------------------------------------
        # Set Up Notebook Container
        #---------------------------------------------------
        self.notebook = Gtk.Notebook()
        self.add(self.notebook)

        #---------------------------------------------------
        # Set Up Notebook Page 1
        #---------------------------------------------------
        # Setup Grid
        gridStart = Gtk.Grid()
        #---------------------------------------------------
        gridStart.set_size_request(400,700)

        imageStart = Gtk.Image()
        imageStart.set_from_file("bigstock-hacker.jpg")

        imageLogo = Gtk.Image()
        imageLogo.set_from_file("lock-orig-50.png")

        labelStart = Gtk.Label()
        labelStart.set_justify(Gtk.Justification.CENTER)
        labelStart.set_markup("\n<big><big><big><b>Catch the Man-in-the-Middle</b></big></big></big>\n\n")

        labelCredit = Gtk.Label()
        labelCredit.set_justify(Gtk.Justification.CENTER)
        labelCredit.set_markup("\nA CyberSecurity Toolkit by Rob Braxman\n(c) Copyright Braxmobile Inc 2020\n")

        buttonSniffStart = Gtk.Button("Start Monitoring Network")
        buttonSniffStart.connect("clicked", self.on_button_sniff_start_clicked)

        buttonSniffStop = Gtk.Button("Stop Monitoring Network")
        buttonSniffStop.connect("clicked", self.on_button_sniff_stop_clicked)

        self.sniffStatusLabel = Gtk.Label()
        self.sniffStatusLabel.set_justify(Gtk.Justification.LEFT)
        self.sniffStatusLabel.set_markup("\n<b><i>Inactive</i></b>")

        # Attach Elements to Grid
        #gridStart.attach(imageLogo,0,0,3,1)
        gridStart.attach(labelStart,0,1,3,1)
        gridStart.attach(imageStart,0,2,3,1)
        gridStart.attach(labelCredit,0,8,3,1)
        gridStart.attach(buttonSniffStart,0,3,3,1)
        gridStart.attach(buttonSniffStop,0,4,3,1)
        gridStart.attach(self.sniffStatusLabel,0,6,3,1)


        #---------------------------------------------------
        # Attach Grid to Notebook Page
        pageStart = gridStart
        pageStart.set_border_width(10)
        pageStart.add(Gtk.Label(''))
        self.notebook.append_page(
            pageStart,
            Gtk.Image.new_from_icon_name(
                "help-about",
                Gtk.IconSize.LARGE_TOOLBAR
            ))




        #---------------------------------------------------
        # Set Up Notebook Page 2
        #---------------------------------------------------
        gridDevice = Gtk.Grid()
        #---------------------------------------------------

        labelDevice = Gtk.Label()
        labelDevice.set_markup("<b>Discovered Network Devices</b>")
        labelDevice.set_justify(Gtk.Justification.LEFT)

        buttonID = Gtk.Button("Identify Device")
        buttonID.connect("clicked", self.on_button_device_id_clicked)


        buttonJam = Gtk.Button("Jam Device")
        buttonJam.connect("clicked", self.on_button_device_jam_clicked)

        buttonViewScan = Gtk.Button("Active Device Scan")
        buttonViewScan.connect("clicked", self.on_button_device_active_scan_clicked)

        buttonPortScan = Gtk.Button("Port Scan")
        buttonPortScan.connect("clicked", self.on_button_device_port_scan_clicked)


        sboxDevice = Gtk.ScrolledWindow()
        sboxDevice.set_border_width(10)
        sboxDevice.set_size_request(400,400)

        self.arpmodel = Gtk.ListStore(str,str,str,str)
        self.arpmodel.set_sort_column_id(0,0)

        self.arpView = Gtk.TreeView(self.arpmodel)

        columnArp = Gtk.TreeViewColumn("IP Address", Gtk.CellRendererText(), text=0)
        self.arpView.append_column(columnArp)

        column2Arp = Gtk.TreeViewColumn("MAC Address", Gtk.CellRendererText(), text=1)
        self.arpView.append_column(column2Arp)

        column3Arp = Gtk.TreeViewColumn("Identity", Gtk.CellRendererText(), text=2)
        self.arpView.append_column(column3Arp)

        column4Arp = Gtk.TreeViewColumn("Mac", Gtk.CellRendererText(), text=3)
        self.arpView.append_column(column4Arp)


        sboxDevice.add_with_viewport(self.arpView)
        select = self.arpView.get_selection()
        select.connect("changed", self.on_tree_selection_changed)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        sboxDevice.set_vadjustment(gadjustment)


        sboxScan = Gtk.ScrolledWindow()
        sboxScan.set_border_width(10)
        sboxScan.set_size_request(400,300)

        self.scanmodel = Gtk.ListStore(str)
        self.scanView = Gtk.TreeView(self.scanmodel)
        self.scanmodel.append(["Listening for Devices"])

        columnScan = Gtk.TreeViewColumn("Scan Data", Gtk.CellRendererText(), text=0)
        self.scanView.append_column(columnScan)

        sboxScan.add_with_viewport(self.scanView)
        select = self.scanView.get_selection()
        select.connect("changed", self.on_tree_selection_changed)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        sboxScan.set_vadjustment(gadjustment)

        gridDevice.attach(labelDevice,1,0,2,1)
        gridDevice.attach(buttonViewScan,1,1,1,1)
        gridDevice.attach(buttonID,1,2,1,1)
        gridDevice.attach(buttonJam,2,1,1,1)
        gridDevice.attach(buttonPortScan,2,2,1,1)
        gridDevice.attach(sboxDevice,1,3,2,1)
        gridDevice.attach(sboxScan,1,4,2,1)

        #---------------------------------------------------
        pageDevice = gridDevice
        pageDevice.set_border_width(10)
        pageDevice.add(Gtk.Label(''))

        self.notebook.append_page(
            pageDevice,
            Gtk.Image.new_from_icon_name(
                "system-search",
                Gtk.IconSize.LARGE_TOOLBAR
            ))



        #---------------------------------------------------
        # Set Up Notebook Page 3 - DNS
        #---------------------------------------------------
        # Setup Grid
        gridDns = Gtk.Grid()

        label3 = Gtk.Label()
        label3.set_markup("<b>Real Time DNS Log</b>")
        label3.set_justify(Gtk.Justification.LEFT)

        sboxDns = Gtk.ScrolledWindow()
        sboxDns.set_border_width(10)
        sboxDns.set_size_request(400,700)

        self.logmodel = Gtk.ListStore(str,str)
        self.logmodel.append(["Initialized",""])

        self.logView = Gtk.TreeView(self.logmodel)

        cellRenderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("DNS Log", cellRenderer, text=0)
        self.logView.append_column(column)

        cellRenderer2 = Gtk.CellRendererText()
        column2 = Gtk.TreeViewColumn("Time Stamp", cellRenderer2, text=1)
        self.logView.append_column(column2)

        sboxDns.add_with_viewport(self.logView)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        sboxDns.set_vadjustment(gadjustment)

        gridDns.attach(label3,1,0,1,1)
        gridDns.attach(sboxDns,1,1,1,1)

        #---------------------------------------------------
        pageDns = gridDns
        pageDns.set_border_width(10)
        pageDns.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageDns, Gtk.Label('DNS Trace'))
        self.notebook.append_page(
            pageDns,
            Gtk.Image.new_from_icon_name(
                "address-book-new",
                Gtk.IconSize.LARGE_TOOLBAR
            ))
        self.notebook.set_show_tabs(True)



        #---------------------------------------------------
        # Set Up Notebook Page 4
        #---------------------------------------------------
        gridMITM = Gtk.Grid()


        labelDnsHist = Gtk.Label()
        labelDnsHist.set_justify(Gtk.Justification.LEFT)
        labelDnsHist.set_markup("<b>DNS History - Unique Domain List</b>")

        sbox = Gtk.ScrolledWindow()
        sbox.set_border_width(10)
        sbox.set_size_request(400,400)


        self.model = Gtk.ListStore(str)


        self.treeView = Gtk.TreeView(self.model)
        column = Gtk.TreeViewColumn("Select a Domain", Gtk.CellRendererText(), text=0)
        self.treeView.append_column(column)
        self.model.set_sort_column_id(0,0)

        sbox.add_with_viewport(self.treeView)
        select = self.treeView.get_selection()
        select.connect("changed", self.on_tree_selection_changed)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        sbox.set_vadjustment(gadjustment)

        labelDomain = Gtk.Label()
        labelDomain.set_markup("<b>Enter Fully Qualified Domain Name</b>")
        labelDomain.set_justify(Gtk.Justification.LEFT)

        self.entry = Gtk.Entry()
        self.entry.set_text("")


        self.check = Gtk.Button("Check for Spoofed Certificate")
        self.check.connect("clicked", self.on_check_clicked)

        self.status = Gtk.Label()
        self.status.set_justify(Gtk.Justification.LEFT)
        self.status.set_markup("\n<i>Scanning DNS Queries</i>")

        gridMITM.attach(labelDnsHist,1,0,1,1)
        gridMITM.attach(sbox,1,1,1,1)
        gridMITM.attach(labelDomain,1,2,1,1)
        gridMITM.attach(self.entry,1,3,1,1)
        gridMITM.attach(self.check,1,4,1,1)
        gridMITM.attach(self.status,1,5,1,1)

        pageMITM = gridMITM
        pageMITM.set_border_width(10)
        pageMITM.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageMITM, Gtk.Label('MITM Check'))
        self.notebook.append_page(
        pageMITM,
        Gtk.Image.new_from_icon_name(
            "application-certificate",
            Gtk.IconSize.LARGE_TOOLBAR
        ))

        if False:
            #---------------------------------------------------
            # Set Up Notebook Page 5
            #---------------------------------------------------
            # Setup Grid
            gridSniff = Gtk.Grid()
            #---------------------------------------------------

            labelSniff = Gtk.Label()
            labelSniff.set_markup("<b>Raw Packet Data</b>")
            labelSniff.set_justify(Gtk.Justification.LEFT)


            sboxSniff = Gtk.ScrolledWindow()
            sboxSniff.set_border_width(10)
            sboxSniff.set_size_request(400,700)

            self.monitormodel = Gtk.ListStore(str,str,str)
            self.monitormodel.append(["Initialized","",""])

            self.monitorView = Gtk.TreeView(self.monitormodel)

            columnMon = Gtk.TreeViewColumn("Device MACAddress", Gtk.CellRendererText(), text=0)
            self.monitorView.append_column(columnMon)

            column2Mon = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=1)
            self.monitorView.append_column(column2Mon)

            column3Mon = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=2)
            self.monitorView.append_column(column3Mon)


            sboxSniff.add_with_viewport(self.monitorView)

            gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
            sboxSniff.set_vadjustment(gadjustment)

            gridSniff.attach(labelSniff,1,0,2,1)
            gridSniff.attach(sboxSniff,1,2,2,1)

            #---------------------------------------------------
            # Attach Grid to Notebook Page

            pageSniff = gridSniff
            pageSniff.set_border_width(10)
            pageSniff.add(Gtk.Label(''))

            self.notebook.append_page(
                pageSniff,
                Gtk.Image.new_from_icon_name(
                    "view-refresh",
                    Gtk.IconSize.LARGE_TOOLBAR
                ))


        #---------------------------------------------------
        # Set Up Notebook Page 6
        #---------------------------------------------------
        gridMITM = Gtk.Grid()


        labelHelp = Gtk.Label()
        labelHelp.set_justify(Gtk.Justification.LEFT)
        labelHelp.set_markup("<b>About Catch MITM</b>\n\n"+
            "\nThis app is used to track unusual traffic or "+
            "\ndevices on your network. Start sniffing "+
            "\nyour network and wait for it to accumulate "+
            "\ndata. \n"+
            "\nIt will record all IP addresses, DNS "+
            "\nrequests, detect devices, track the traffic "+
            "\nwith external IP addresses, allow you to "+
            "\ncheck for spoofed (fake) https certificates. "+
            "\nAnd identify all devices in your subnet. \n"+
            "\nYou can manually assign names to devices you "+
            "\nrecognize. Then if an unusual device "+
            "\nappears, it may be an attacker. You can use "+
            "\nthe JAM feature to shutdown network access "+
            "\nby that device. \n"+
            "\nLeave this running when you're not using  " +
            "\nyour device. It will detect malware that's " +
            "\ncommunicating in the background. \n"+
            "\nBy default, this only sniffs your own "+
            "\nlocal subnet. ")

        gridMITM.attach(labelHelp,1,0,1,1)

        pageMITM = gridMITM
        pageMITM.set_border_width(10)
        pageMITM.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageMITM, Gtk.Label('MITM Check'))
        self.notebook.append_page(
        pageMITM,
        Gtk.Image.new_from_icon_name(
            "system-help",
            Gtk.IconSize.LARGE_TOOLBAR
        ))



    def on_main_window_deleted(self, * args):
        print('Destroy Main Window')

        Gtk.main_quit()
        #self.scapy.kill()
        sys.exit()

    # Start GTK Specific
    def on_tree_selection_changed(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            self.entry.set_text(model[treeiter][0])
            self.status.set_text("")
        cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
        self.get_root_window().set_cursor(cursor)

    def SearchTreeRows(self,store, searchstr):
        #print("\nsearch>%s"%searchstr)
        try:
            treeiter = store.get_iter_first()
            while treeiter != None:

                if store[treeiter][0] ==searchstr:
                    #print("found in:%s"%str(store[treeiter][:]))
                    return(False)

                #print("searched:%s"%str(store[treeiter][:]))
                treeiter = store.iter_next(treeiter)
        except:
            print('Dup Error')
            return(True)
        return(True)

    def cleanupModels(self):


        #while (len(self.monitormodel) > 100000):
        #    n = len(self.monitormodel)
        #    treeiter = self.monitormodel.iter_nth_child(None, 501 - 1)
        #    if treeiter:
        #        self.monitormodel.remove(treeiter)

        while (len(self.logmodel) > 2000):
            if self.sniffStatus == True:
                self.monitorLock.acquire()
                n = len(self.logmodel)
                treeiter = self.logmodel.iter_nth_child(None, 501 - 1)
                if treeiter:
                    self.logmodel.remove(treeiter)
                self.monitorLock.release()
            time.sleep(10)
        return self.netDevice

    # END GTK Specific


    #--------------------------------------------------------------------
    # On-button-clicked Section
    #--------------------------------------------------------------------

    def on_check_clicked(self, button):
        self.certcheck()

    def on_button_device_port_scan_clicked(self,button):
        if self.portScanningStatus:
            self.portScanningStatus = False
            self.scanmodel.append(["Stopping Port Scan"])

            return

        selection = self.arpView.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            target_ip = self.arpmodel.get_value(treeiter,0)
            target_ip = target_ip.replace("\n","")
            print("Port Scan IP Address "+target_ip )
            self.info_dialog("Port Scan","device IP "+target_ip,"scan")
        return

    def on_button_device_jam_clicked(self, button):
        selection = self.arpView.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            self.status.set_text("")
            value = self.arpmodel.get_value(treeiter,0)
            value = value.replace("\n","")
            print("Jam IP Address "+value )
            self.info_dialog("Jamming Device","device IP "+value,"jam")

    def on_button_device_id_clicked(self, button):
        self.setvalue_dialog("Set Identity","Give Device a Custom\nName","id")

    def on_button_sniff_start_clicked(self,button):
        self.sniffStatusLabel.set_markup("\n<b><i>Monitoring active.\nSwitch tabs to view data.</i></b>")
        #self.monitormodel.clear()
        self.sniffStatus = True
        self.scapy = threading.Thread(target=self.start_sniff, )
        self.scapy.daemon = True
        # daemons get automatically closed when app exits
        self.scapy.start()

        #self.scapyPing = threading.Thread(target=self.ping_scan(True), )
        #self.scapyPing.daemon = True
        # daemons get automatically closed when app exits
        #self.scapyPing.start()


    def on_button_sniff_stop_clicked(self, button):
        self.sniffStatusLabel.set_markup("\n<b><i>Network sniffing paused. Data retained.</i></b>")
        self.sniffStatus = False

    def on_button_device_active_scan_clicked(self, button):
        self.info_dialog("Active Device Search", "Perform active device\nsearch with ARP?\n\nAfter the request is made\nit takes a moment before\ndevices get reported." , "activearp")

    #--------------------------------------------------------------------
    # End -On-button-clicked Section
    #--------------------------------------------------------------------

    def certcheck(self):

        cursor = Gdk.Cursor.new(Gdk.CursorType.WATCH)
        self.get_root_window().set_cursor(cursor)

        #addr = 'brax.me'
        addr = self.entry.get_text()
        if (addr == ''):
            print('\nInvalid Domain\n')
            cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
            self.get_root_window().set_cursor(cursor)
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        wrappedSocket = ssl.wrap_socket(sock)

        try:
            wrappedSocket.connect((addr, 443))
        except:
            print('Cert Check Exception Error')
            response = False
        else:
            der_cert_bin = wrappedSocket.getpeercert(True)
            pem_cert = ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
            #print(pem_cert)

            # Thumbprint
            thumb_md5 = hashlib.md5(der_cert_bin).hexdigest()
            thumb_sha1 = hashlib.sha1(der_cert_bin).hexdigest()
            thumb_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
            #print("MD5: " + thumb_md5)
            #print("SHA1: " + thumb_sha1)
            print("SHA256: " + thumb_sha256)

            domain = self.entry.get_text()
            response = requests.get("https://brax.me/certcheck.php?url="+domain)
            json = response.json()
            dnslist = json['dns']
            fingerprint256 = json['fingerprint2']
            fingerprint256 = fingerprint256.replace(" ","")

            if( fingerprint256 == ''):
                print('No HTTPS certificate to check')
                self.status.set_markup("<big><big><i><b>\nNo HTTPS Website to Check\n<</b></i>/big></big>")
                cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
                self.get_root_window().set_cursor(cursor)
                return

            dns_array = self.dns_resolve(addr)
            dns_array_remote = dnslist.split("\n")
            if(self.compareDNS(dns_array, dns_array_remote)):
                print('Matching DNS')
                dns_spoof_test = 'Safe - No DNS Spoofing'
            else:
                print('DNS Possible Spoofing')
                dns_spoof_test = 'Possible DNS Spoof or Ad Blocker'


            if (thumb_sha256 == fingerprint256):
                print("remote "+fingerprint256+"\r\n"+"local  "+thumb_sha256+"\r\n"+" success. No MITM"+"\n"+dns_spoof_test)
                self.status.set_markup("<big><big><b><i>\nSafe - No HTTPS MITM\n"+dns_spoof_test+"</i></b></big></big>")
                cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
                self.get_root_window().set_cursor(cursor)
            else:
                print("remote "+fingerprint256+"\r\n"+"local  "+thumb_sha256+"\r\n"+" failed. MITM found"+"\n"+dns_spoof_test)
                self.status.set_markup("<big><big><b><i>\nPossible HTTPS MITM or Redirect\n"+dns_spoof_test+"</i></b></big></big>")
                cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
                self.get_root_window().set_cursor(cursor)



        wrappedSocket.close()

    def compareDNS(self, dns_array, dns_array_remote):
        for ip in dns_array:
            for ipremote in dns_array_remote:
                if ip == ipremote:
                    return True

    def querysniff(self,pkt):

        if (pkt.haslayer(DNSQR) or pkt.haslayer(DNSRR) ) and self.jamStatus == False:
            try:
                #print(pkt.summary())
                dnsqr = pkt.getlayer(DNSQR).qname

                #print(pkt.getlayer(DNSQR).qtype)
                #print(pkt.getlayer(DNSQR).qclass)

                #this layer is not working with sprintf- though they are valid variables -
                #dnsname = pkt.sprintf("%DNSQR.qname% %DNSRR.rdata% ")
                #print(dnsname)

                dnsname = "".join( chr(x) for x in dnsqr)
                dnsname = (dnsname+" ").replace(". ","")
            except:
                print('Error in HasLayer DNSQR')
                return

            try:
                #if dstring.find(".local") != -1:
                #    return
                #if dstring.find("in-addr.arpa") == -1:
                #    return

                #remove trailing .
                #dstring = (dstring+" ").replace(". ","")
                if dnsname != self.lastDomain and dnsname.find(".local") == -1 and dnsname.find("in-addr.arpa") == -1:
                    self.lastDomain = dnsname

                    noDups = self.SearchTreeRows(self.model, dnsname)
                    if noDups:
                        self.model.append([dnsname])
                    datestring = datetime.now().strftime("%H:%M:%s %Y/%m/%d ")
                    logentry = dnsname+" "+datestring
                    #print(logentry)
                    treeiter = self.logmodel.get_iter_first()
                    self.logmodel.insert_before(treeiter, [dnsname, datestring])

            except:
                print('Error in DNSQR')

        if pkt.haslayer(ARP):

            try:
                mac = pkt[ARP].hwsrc

                if pkt[ARP].psrc in self.deviceList:
                    return
                self.deviceList[pkt[ARP].psrc] = mac
                macshort = mac[0:8]
                if macshort in self.vendorList:
                    macvendortext = self.vendorList[macshort]
                else:
                    macvendor = requests.get("https://brax.me/prod/macmanuf.php?mac="+mac)
                    macvendortext = macvendor.text
                    self.vendorList[macshort] = macvendor.text

                devicedesc = ''
                if mac in self.deviceDescList:
                    devicedesc = self.deviceDescList[mac]

                macfakelist = {
                }
                if mac in macfakelist:
                    macfake = macfakelist[mac]
                else:
                    macfake = mac
                try:
                    hostname, alias, ipaddrlist = socket.gethostbyaddr( pkt[ARP].psrc )
                except:
                    #print('Unknown Host '+pkt[ARP].psrc)
                    hostname = ''

                treeiter = self.arpmodel.get_iter_first()
                self.arpmodel.insert_before(treeiter,[pkt[ARP].psrc+"\n\n", macfake+"\n"+macvendortext+"\n"+hostname,  devicedesc+"\n\n", mac+"\n\n" ])

                #print(bytes(pkt[ARP]))
            except error:
                print('Arp Error')
                return

        if pkt.haslayer(IP) and self.jamStatus == False:
            proto =  pkt.sprintf("%IP.proto%")

            sportraw = pkt.sprintf("%IP.sport%")
            dportraw = pkt.sprintf("%IP.dport%")
            #ignore MDNS
            if sportraw == int(5353):
                return
            sport = "["+sportraw+"]"
            dport = "["+dportraw+"]"
            if sportraw in self.portList:
                sport = "["+self.portList[sportraw]+"]"
            if dportraw in self.portList:
                dport = "["+self.portList[dportraw]+"]"
            if sportraw != '??' and int(sportraw) > 30000:
                sport = ""
            if dportraw != '??' and int(dportraw) > 30000:
                dport = ""

            src = pkt[IP].src
            if src not in self.deviceList and (src[0:8]=='192.168.' or src[0:5]=='10.0.'):
                #print(src+' not in device list')
                arping(src)

            try:
                data = pkt.sprintf(proto+" %IP.src%"+sport+" --> %IP.dst%"+dport+"")

                #data = pkt.summary()
                #treeiter = self.monitormodel.get_iter_first()
                #if data:
                    #self.monitorLock.acquire()
                    #self.monitormodel.insert_before(treeiter, [data, "", "" ])
                    #self.monitorLock.release()
            except error:
                print('TCP Error')

            return


    def start_sniff(self):
        #repeat discovery in case network changes
        self.discoverNetDevice()

        self.discovered_if = self.setNetDevice()
        #print(self.discovered_if)
        interface = self.discovered_if
        #interface = ""
        if interface !='':
            sniff(iface = interface, filter = "", prn = self.querysniff, store = 0, stop_filter=self.sniff_stopfilter)
        else:
            sniff(filter="", prn=self.querysniff, store=0, stop_filter=self.sniff_stopfilter)
        print("\n[*] Shutting sniff...")


    def sniff_stopfilter(self, pkt):
        if self.sniffStatus == False:
            return True
        return False


    def dns_resolve(self,domain):
        myResolver = dns.resolver.Resolver()
        myAnswers = myResolver.query(domain,"A")
        statusText = self.status.get_text()
        dns_array = []
        for rdata in myAnswers:
            print(rdata)
            print(type(rdata))
            statusText = statusText+"\n"+rdata.to_text()
            dns_array.append(rdata.to_text())
        self.status.set_text(statusText)
        return dns_array


    def discoverNetDevice(self):
        dict_if = psutil.net_if_addrs()
        #print('Discovered If Interfaces')
        self.discovered_if = []
        for key in dict_if:

            inet = dict_if[key][0][1]
            netmask = dict_if[key][0][2]
            if inet is not None and netmask is not None and inet != '127.0.0.1':
                print(self.subnet+" "+self.netmask)

            #print('\n'+key, '->', dict_if[key][0])
            if key != 'lo':
                self.discovered_if.append(key)
            if key[0] == 'w':
                self.netmask = netmask
                self.subnet = inet
                #print('\nInet' + self.subnet)
                #print('\nNetmask' + self.netmask)
                #print('\nDiscovered Wifi ='+key)
                self.netDevice = key
                f = open(self.appdataDir+"/wifi-device.conf","w")
                f.write(key)
                f.close()
                subprocess.call(["chmod","0755",self.appdataDir+"/wifi-device.conf"])
    def setNetDevice(self):

        f = open(self.appdataDir+"/wifi-device.conf","r")
        self.netDevice = f.read().replace("\n","")


    def info_dialog(self, title, message, action):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
                                   Gtk.ButtonsType.OK_CANCEL, title)
        dialog.format_secondary_text(message)
        response = dialog.run()

        if response == Gtk.ResponseType.OK:
            if action == 'jam':
                print("Jamming")
                dialog.destroy()
                self.jamStatus = True

                selection = self.arpView.get_selection()
                model, treeiter = selection.get_selected()
                if treeiter is not None:
                    mac = self.arpmodel.get_value(treeiter, 3)
                    mac = mac.replace("\n","")
                    ip = self.arpmodel.get_value(treeiter, 0)
                    ip = ip.replace("\n","")
                    print(mac+"/"+ip)

                    self.scapyJam = threading.Thread(target=self.jam_loop,args=(mac, ip) )
                    self.scapyJam.daemon = True
                    # daemons get automatically closed when app exits
                    self.scapyJam.start()

                    self.msg_dialog("Jamming","Jam inifinitely. Click OK to Stop","jam")
                    self.scanmodel.clear()
                    self.scanmodel.append(["Jammed Network for " + ip])
                return
            elif action == 'scan':
                #print("Scanning")
                dialog.destroy()
                self.jamStatus = True

                selection = self.arpView.get_selection()
                model, treeiter = selection.get_selected()
                if treeiter is not None:
                    target_ip = self.arpmodel.get_value(treeiter, 0)
                    target_ip = target_ip.replace("\n","")

                    self.scapyScan = threading.Thread(target=self.port_scan, args=(target_ip,))
                    self.scapyScan.daemon = True
                    # daemons get automatically closed when app exits
                    self.scapyScan.start()

                return
            elif action == 'activearp':
                #print("Scanning")
                dialog.destroy()

                self.scapyPing = threading.Thread(target=self.ping_scan, args=())
                self.scapyPing.daemon = True
                # daemons get automatically closed when app exits
                self.scapyPing.start()

                return
            else:
                print("No Action")
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancelled")
        dialog.destroy()

    def setvalue_dialog(self, title, message, action):

        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
                                   Gtk.ButtonsType.OK_CANCEL, title)
        dialog.format_secondary_text(message)
        userEntry = Gtk.Entry()
        dialogBox = dialog.get_content_area()
        dialogBox.pack_end(userEntry, False, False, 0)

        selection = self.arpView.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            hostname = ''
            ip = self.arpmodel.get_value(treeiter, 0)
            try:
                hostname, x, y = socket.gethostbyaddr(ip)
            except:
                hostname = ''
                #print('Unknown host '+ip)
            userEntry.set_text(hostname)

        dialog.show_all()
        response = dialog.run()
        devicedesc = userEntry.get_text()

        if response == Gtk.ResponseType.OK:

            selection = self.arpView.get_selection()
            model, treeiter = selection.get_selected()
            if treeiter is not None:
                mac = self.arpmodel.get_value(treeiter, 3)
                mac = mac.replace("\n","")

                self.arpmodel.set_value(treeiter, 2, devicedesc+"\n\n")
                self.deviceDescList[mac] = devicedesc
                pickle.dump(self.deviceDescList, open(self.appdataDir+"/_devicelist.dict", "wb"))
                subprocess.call(["chmod","0755",self.appdataDir+"/_devicelist.dict"])

        elif response == Gtk.ResponseType.CANCEL:
            print("Cancelled")
        dialog.destroy()

    def msg_dialog(self, title, message, action):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
                                   Gtk.ButtonsType.OK, title)
        dialog.format_secondary_text(message)
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            print("OK")
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancelled")
        dialog.destroy()
        if action == 'jam':
            self.jamStatus = False
        #if action == 'general':
        #   no action
        print('Stopped')

    def jam_loop(self, xhwdst, xpdst):
        if self.sniffStatus == False:
            self.msg_dialog("Jam Device", "Please start sniffing network first","general")
            return
        xhwsrc = get_if_hwaddr(conf.iface)
        xpsrc = "192.168.1.1"
        #xhwsrc = "11:11:11:11:11:11:11:11"
        while self.jamStatus:
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + xpdst)
            packet = Ether()/ARP(op="who-has",hwsrc=xhwsrc, hwdst=xhwdst, psrc=xpsrc, pdst=xpdst)
            sendp(packet, verbose=False)
            x2pdst = "192.168.1.1"
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + x2pdst)
            packet = Ether()/ARP(op="who-has",hwsrc=xhwsrc, psrc=xpsrc, pdst=x2pdst)
            sendp(packet,verbose=False)
            x3pdst = "192.168.1.91"
            x3hwsrc = "11:11:11:11:11:11:11:11"
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + x3pdst)
            packet = Ether()/ARP(op="who-has",hwsrc=x3hwsrc, psrc=xpsrc, pdst=xpdst)
            sendp(packet, verbose=False)
            time.sleep(.3)
            #print(bytes(response))
        return

    def ping_scan(self):
        if self.sniffStatus == False:
            self.msg_dialog("Active Device Scan", "Please start sniffing network first","general")
            return

        inet = self.subnet.split(".")
        #print(self.subnet)
        subnet = self.netmask.split(".")
        TIMEOUT = 2
        conf.verb = 0
        if int(subnet[2]) == 255:
            ip3range = [ int( inet[2] )]
        else:
            ip3range = range(0,255)
        ip4range = range(1,255)
        self.scanmodel.clear()
        print("Active device scan")
        self.scanmodel.append(["Active Device Search "])
        self.scanmodel.append( ["ARP " + inet[0]+"."+inet[1]+"."+str(ip3range)+"."+str(ip4range)+""])
        for ip3 in ip3range:
            for ip4 in ip4range:
                ip_dst = subnet[0]+"."+subnet[1]+"."+str(ip3)+"."+str(ip4)
                #packet = IP(dst=ip_dst) / ICMP()
                #print(sr1(packet))
                packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_dst)
                sendp(packet,verbose=False)
                #print('ARP '+ip_dst)
        self.scanmodel.append( ["ARP Requests Completed"])
        self.scanmodel.append( ["Listening for Answers"])
        return


    def port_scan(self, target_ip):
        if self.sniffStatus == False:
            self.msg_dialog("Device Port Scan", "Please start sniffing network first","general")
            return
        print('Scan '+target_ip)
        self.scanmodel.clear()
        self.scanmodel.append(["Port Scan Started for "+target_ip+"."])

        #set flag to initiate scan
        self.portScanningStatus = True

        for port in self.portList:
            if not self.portScanningStatus:
                self.scanmodel.append(["Port Scan Stopped"])
                return
            portstatus = self.port_scan_single(target_ip, int(port))
            if portstatus:

                if int(port) == 22 or int(port) == 5900:
                    self.scanmodel.append(["LinuxLike"])
                    print("LinuxLike")
                if int(port) == 80 or int(port) == 443 or int(port) == 8080 :
                    self.scanmodel.append(["HasWebservice"])
                    print("HasWebservice")
                if int(port) == 53 :
                    self.scanmodel.append(["Gateway"])
                    print("Gateway")
        self.scanmodel.append(["Port Scan Complete"])
        print("Quick Port Scan Complete")
        self.portScanningStatus = False
        return

    def port_scan_single(self, target_ip, port):
        dst_ip = target_ip.replace("\n","")
        src_port = RandShort()
        dst_port = port

        try:
            #Send SYN FLAG to port
            stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=10, verbose=False)
            #print("Type"+str(type(stealth_scan_resp)))

            if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
                print("Filtered")
                return False
            elif (stealth_scan_resp.haslayer(TCP)):
                #print('Has Layer TCP')
                #print(stealth_scan_resp.getlayer(TCP).flags)
                if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                    #Scan stopped
                    if not self.portScanningStatus:
                        return False
                    #wait for RST + ACK
                    send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), timeout=10, verbose=False)
                    print("Open "+str(port))
                    self.scanmodel.append(["Open Port "+str(port)+" "+self.portList[str(port)]])
                    return True
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                print ("Closed"+str(port))
                self.scanmodel.append(["Closed Port"+str(port)])
                return False
            elif (stealth_scan_resp.haslayer(ICMP)):
                if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and
                int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    print ("Filtered"+str(port))
                    return False
        except:
            print("Error "+str(port)+" "+target_ip)
            self.portScanningStatus = False
            self.scanmodel.append(["Unreachable"])
            return False
        return False


win = MainWindow()
win.connect("destroy", win.on_main_window_deleted)
win.show_all()
Gtk.main()
