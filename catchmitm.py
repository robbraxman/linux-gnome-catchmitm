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
    portList = {'22':'ssh','443':'https','80':'http','53':'dns','143':'imap','465':'smtp/s','993':'imap/s','110':'pop3',
                '5353':'mdns','1900':'upnp'
               }
    deviceDescList = {}
    monitorLock = False
    sniffStatus = False
    jamStatus = False
    subnet = ""
    netmask = ""
    installDir = "/home/linux/Documents/PythonGnome/"

    def __init__(self):

        #os.system('clear')
        print('Starting Catch MITM')

        self.monitorLock = threading.Semaphore()

        try:
            self.deviceDescList = pickle.load(open("_devicelist.dict", "rb"))
        except:
            print('No devlicelist')

        Gtk.Window.__init__(self, title="Catch Man-in-the-Middle")
        self.set_size_request(400, 600)
        self.set_border_width(10)

        self.timeout_id = None
        self.set_icon_from_file("lock-orig.png")

        #---------------------------------------------------
        self.notebook = Gtk.Notebook()
        self.add(self.notebook)

        #---------------------------------------------------
        #---------------------------------------------------
        gridMenu = Gtk.Grid()
        gridMenu.set_size_request(400,600)

        self.imageMenu = Gtk.Image()
        self.imageMenu.set_from_file("bigstock-hacker.jpg")

        self.imageLogo = Gtk.Image()
        self.imageLogo.set_from_file("lock-orig-50.png")

        self.labelMenu = Gtk.Label()
        self.labelMenu.set_justify(Gtk.Justification.CENTER)
        self.labelMenu.set_markup("\n<big><big><big><b>Catch the Man-in-the-Middle</b></big></big></big>\n\n")

        gridMenu.attach(self.imageLogo,0,0,3,1)
        gridMenu.attach(self.labelMenu,0,1,3,1)

        #self.add(self.iconView)
        gridMenu.attach(self.imageMenu,0,2,3,1)

        self.labelCredit = Gtk.Label()
        self.labelCredit.set_justify(Gtk.Justification.CENTER)
        self.labelCredit.set_markup("\nA CyberSecurity Toolkit by Rob Braxman\n(c) Copyright Braxmobile Inc 2019\n")
        gridMenu.attach(self.labelCredit,0,3,3,1)
        #gridMenu.attach(self.sboxDevice,1,2,2,1)

        #---------------------------------------------------
        self.pageMenu = gridMenu
        self.pageMenu.set_border_width(10)
        self.pageMenu.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageMenu, Gtk.Label('Start'))
        self.notebook.append_page(
            self.pageMenu,
            Gtk.Image.new_from_icon_name(
                "help-about",
                Gtk.IconSize.LARGE_TOOLBAR
            ))



        #---------------------------------------------------
        #---------------------------------------------------
        gridSniff = Gtk.Grid()

        self.labelSniff = Gtk.Label()
        self.labelSniff.set_markup("<b>Sniff Packet Monitor</b>")
        self.labelSniff.set_justify(Gtk.Justification.LEFT)
        gridSniff.attach(self.labelSniff,1,0,2,1)

        self.buttonStart = Gtk.Button("Start Sniff")
        self.buttonStart.connect("clicked", self.on_buttonStart_clicked)
        gridSniff.attach(self.buttonStart,1,1,1,1)

        self.buttonStop = Gtk.Button("Stop Sniff")
        self.buttonStop.connect("clicked", self.on_buttonStop_clicked)
        gridSniff.attach(self.buttonStop,2,1,1,1)


        self.sboxSniff = Gtk.ScrolledWindow()
        self.sboxSniff.set_border_width(10)
        self.sboxSniff.set_size_request(400,600)

        self.monitormodel = Gtk.ListStore(str,str,str)
        self.monitormodel.append(["Initialized","",""])

        self.monitorView = Gtk.TreeView(self.monitormodel)

        columnMon = Gtk.TreeViewColumn("Device MACAddress", Gtk.CellRendererText(), text=0)
        self.monitorView.append_column(columnMon)

        column2Mon = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=1)
        self.monitorView.append_column(column2Mon)

        column3Mon = Gtk.TreeViewColumn("", Gtk.CellRendererText(), text=2)
        self.monitorView.append_column(column3Mon)


        self.sboxSniff.add_with_viewport(self.monitorView)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        self.sboxSniff.set_vadjustment(gadjustment)

        gridSniff.attach(self.sboxSniff,1,2,2,1)

        #---------------------------------------------------
        self.pageSniff = gridSniff
        self.pageSniff.set_border_width(10)
        self.pageSniff.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageSniff, Gtk.Label('Sniff'))
        self.notebook.append_page(
            self.pageSniff,
            Gtk.Image.new_from_icon_name(
                "view-refresh",
                Gtk.IconSize.LARGE_TOOLBAR
            ))


        #---------------------------------------------------
        #---------------------------------------------------
        gridDevice = Gtk.Grid()
        #self.add(grid3)

        self.labelDevice = Gtk.Label()
        self.labelDevice.set_markup("<b>Network Device Scan</b>")
        self.labelDevice.set_justify(Gtk.Justification.LEFT)
        gridDevice.attach(self.labelDevice,1,0,2,1)

        self.buttonID = Gtk.Button("Identify Device")
        self.buttonID.connect("clicked", self.on_buttonID_clicked)
        gridDevice.attach(self.buttonID,1,1,1,1)

        self.buttonJam = Gtk.Button("Jam Device")
        self.buttonJam.connect("clicked", self.on_buttonJam_clicked)
        gridDevice.attach(self.buttonJam,2,1,1,1)

        self.buttonViewScan = Gtk.Button("View Last Scan")
        self.buttonViewScan.connect("clicked", self.on_buttonID_clicked)
        gridDevice.attach(self.buttonViewScan,1,2,1,1)

        self.buttonPortScan = Gtk.Button("Port Scan")
        self.buttonPortScan.connect("clicked", self.on_buttonPortScan_clicked)
        gridDevice.attach(self.buttonPortScan,2,2,1,1)



        self.sboxDevice = Gtk.ScrolledWindow()
        self.sboxDevice.set_border_width(10)
        self.sboxDevice.set_size_request(400,600)

        self.arpmodel = Gtk.ListStore(str,str,str,str)
        self.arpmodel.append(["Initialized","","",""])
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


        self.sboxDevice.add_with_viewport(self.arpView)
        select = self.arpView.get_selection()
        select.connect("changed", self.on_arp_selection_changed)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        self.sboxDevice.set_vadjustment(gadjustment)

        gridDevice.attach(self.sboxDevice,1,3,2,1)

        #---------------------------------------------------
        self.pageDevice = gridDevice
        self.pageDevice.set_border_width(10)
        self.pageDevice.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageDevice, Gtk.Label('Device Scan'))
        self.notebook.append_page(
            self.pageDevice,
            Gtk.Image.new_from_icon_name(
                "system-search",
                Gtk.IconSize.LARGE_TOOLBAR
            ))



        #---------------------------------------------------
        #---------------------------------------------------
        gridDns = Gtk.Grid()
        #self.add(grid2)

        self.label3 = Gtk.Label()
        self.label3.set_markup("<b>Real Time DNS Log</b>")
        self.label3.set_justify(Gtk.Justification.LEFT)
        gridDns.attach(self.label3,1,0,1,1)

        self.sboxDns = Gtk.ScrolledWindow()
        self.sboxDns.set_border_width(10)
        self.sboxDns.set_size_request(400,600)

        self.logmodel = Gtk.ListStore(str,str)
        self.logmodel.append(["Initialized",""])

        self.logView = Gtk.TreeView(self.logmodel)

        cellRenderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("DNS Log", cellRenderer, text=0)
        self.logView.append_column(column)

        cellRenderer2 = Gtk.CellRendererText()
        column2 = Gtk.TreeViewColumn("Time Stamp", cellRenderer2, text=1)
        self.logView.append_column(column2)

        self.sboxDns.add_with_viewport(self.logView)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        self.sboxDns.set_vadjustment(gadjustment)

        gridDns.attach(self.sboxDns,1,1,1,1)

        #---------------------------------------------------
        self.pageDns = gridDns
        self.pageDns.set_border_width(10)
        self.pageDns.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageDns, Gtk.Label('DNS Trace'))
        self.notebook.append_page(
            self.pageDns,
            Gtk.Image.new_from_icon_name(
                "address-book-new",
                Gtk.IconSize.LARGE_TOOLBAR
            ))
        self.notebook.set_show_tabs(True)



        #---------------------------------------------------
        #---------------------------------------------------
        gridMITM = Gtk.Grid()


        self.labelDnsHist = Gtk.Label()
        self.labelDnsHist.set_justify(Gtk.Justification.LEFT)
        self.labelDnsHist.set_markup("<b>DNS History - Scanned Domain List</b>")
        gridMITM.attach(self.labelDnsHist,1,0,1,1)

        self.sbox = Gtk.ScrolledWindow()
        self.sbox.set_border_width(10)
        self.sbox.set_size_request(400,400)
        gridMITM.attach(self.sbox,1,1,1,1)

        self.model = Gtk.ListStore(str)


        self.treeView = Gtk.TreeView(self.model)
        column = Gtk.TreeViewColumn("Select a Domain", Gtk.CellRendererText(), text=0)
        self.treeView.append_column(column)
        self.model.set_sort_column_id(0,0)
        self.sbox.add_with_viewport(self.treeView)
        select = self.treeView.get_selection()
        select.connect("changed", self.on_tree_selection_changed)

        gadjustment = Gtk.Adjustment(value=0, lower=0, upper=100,step_incr=1,page_incr=20, page_size=20)
        self.sbox.set_vadjustment(gadjustment)

        self.labelDomain = Gtk.Label()
        #self.label.set_text("Enter Fully Qualified Domain Name")
        self.labelDomain.set_markup("<b>Enter Fully Qualified Domain Name</b>")
        self.labelDomain.set_justify(Gtk.Justification.LEFT)
        gridMITM.attach(self.labelDomain,1,2,1,1)

        self.entry = Gtk.Entry()
        self.entry.set_text("")
        gridMITM.attach(self.entry,1,3,1,1)

        self.check = Gtk.Button("Check for MITM")
        self.check.connect("clicked", self.on_check_clicked)
        gridMITM.attach(self.check,1,4,1,1)


        self.status = Gtk.Label()
        self.status.set_justify(Gtk.Justification.LEFT)
        self.status.set_markup("\n<i>Scanning DNS Queries</i>")
        gridMITM.attach(self.status,1,5,1,1)

        self.pageMITM = gridMITM
        self.pageMITM.set_border_width(10)
        self.pageMITM.add(Gtk.Label(''))
        #self.notebook.append_page(self.pageMITM, Gtk.Label('MITM Check'))
        self.notebook.append_page(
        self.pageMITM,
        Gtk.Image.new_from_icon_name(
            "application-certificate",
            Gtk.IconSize.LARGE_TOOLBAR
        ))









        #---------------------------------------------------
        os.system("sudo ifconfig wlp1s0 promisc")

        #---------------------------------------------------

        cleanupThread = threading.Thread(target=self.treeCleanup, )
        cleanupThread.daemon = True
        #daemons get automatically closed when app exits
        cleanupThread.start()


    def on_MainWindow_deleted(self, * args):
        print('Destroy Main Window')

        Gtk.main_quit()
        #self.scapy.kill()
        sys.exit()

    def on_check_clicked(self, button):
        self.certcheck()

    def on_buttonPortScan_clicked(self,button):
        selection = self.arpView.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            target_ip = self.arpmodel.get_value(treeiter,0)
            print("Port Scan IP Address "+target_ip )
            self.info_dialog("Port Scan","device IP "+target_ip,"scan")
        return

    def on_buttonJam_clicked(self, button):
        selection = self.arpView.get_selection()
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            self.status.set_text("")
            value = self.arpmodel.get_value(treeiter,0)
            print("Jam IP Address "+value )
            self.info_dialog("Jamming Device","device IP "+value,"jam")

    def on_buttonID_clicked(self, button):
        self.setvalue_dialog("Set Identity","Device Description","id")

    def on_tree_selection_changed(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            self.entry.set_text(model[treeiter][0])
            self.status.set_text("")
        cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
        self.get_root_window().set_cursor(cursor)

    def on_arp_selection_changed(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter is not None:
            self.entry.set_text(model[treeiter][0])
            self.status.set_text("")
        cursor = Gdk.Cursor.new(Gdk.CursorType.ARROW)
        self.get_root_window().set_cursor(cursor)

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
                    hostname = 'Unknown'

                treeiter = self.arpmodel.get_iter_first()
                self.arpmodel.insert_before(treeiter,[pkt[ARP].psrc, macfake+"\n"+macvendortext+"\n"+hostname,  devicedesc, mac ])
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
                treeiter = self.monitormodel.get_iter_first()
                if data:
                    self.monitorLock.acquire()
                    self.monitormodel.insert_before(treeiter, [data, "", "" ])
                    self.monitorLock.release()
            except error:
                print('TCP Error')

            return


    def start_sniff(self):
        self.discovered_if = self.setNetDevice()
        print(self.discovered_if)
        interface = self.discovered_if
        interface = ""
        if interface !='':
            sniff(iface = interface, filter = "", prn = self.querysniff, store = 0, stop_filter=self.sniff_stopfilter)
        else:
            sniff(filter="", prn=self.querysniff, store=0, stop_filter=self.sniff_stopfilter)
        print("\n[*] Shutting sniff...")

    def on_buttonStart_clicked(self,button):
        self.monitormodel.clear()
        self.sniffStatus = True
        self.scapy = threading.Thread(target=self.start_sniff, )
        self.scapy.daemon = True
        # daemons get automatically closed when app exits
        self.scapy.start()

        self.scapyPing = threading.Thread(target=self.ping_scan, )
        self.scapyPing.daemon = True
        # daemons get automatically closed when app exits
        self.scapyPing.start()


    def on_buttonStop_clicked(self, button):
        self.sniffStatus = False

    def sniff_stopfilter(self, pkt):
        if self.sniffStatus == False:
            return True
        return False

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

    def setNetDevice(self):
        dict_if = psutil.net_if_addrs()
        print('Discovered If Interfaces')
        self.discovered_if = []
        for key in dict_if:

            inet = dict_if[key][0][1]
            netmask = dict_if[key][0][2]

            if inet is not None and netmask is not None and inet != '127.0.0.1':
                self.subnet = inet
                self.netmask = netmask
                print(self.subnet+" "+self.netmask)
            #print('\n'+key, '->', dict_if[key][0])
            if key != 'lo':
                self.discovered_if.append(key)

        f = open(self.installDir+"wifi-device.conf","r")
        wlan = f.read().replace("\n","")There
            while (len(self.monitormodel) > 100000):
                n = len(self.monitormodel)
                treeiter = self.monitormodel.iter_nth_child(None, 501 - 1)
                if treeiter:
                    self.monitormodel.remove(treeiter)

            while (len(self.logmodel) > 2000):
                if self.sniffStatus == True:
                    self.monitorLock.acquire()
                    n = len(self.logmodel)
                    treeiter = self.logmodel.iter_nth_child(None, 501 - 1)
                    if treeiter:
                        self.logmodel.remove(treeiter)
                    self.monitorLock.release()
            time.sleep(10)

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
                    ip = self.arpmodel.get_value(treeiter, 0)
                    print(mac+"/"+ip)

                    self.scapyJam = threading.Thread(target=self.jam_loop,args=(mac, ip) )
                    self.scapyJam.daemon = True
                    # daemons get automatically closed when app exits
                    self.scapyJam.start()

                    self.msg_dialog("Jamming","Jam inifinitely. Click OK to Stop")
                return
            elif action == 'scan':
                print("Scanning")
                dialog.destroy()
                self.jamStatus = True

                selection = self.arpView.get_selection()
                model, treeiter = selection.get_selected()
                if treeiter is not None:
                    target_ip = self.arpmodel.get_value(treeiter, 0)

                    self.scapyScan = threading.Thread(target=self.port_scan, args=(target_ip,) )
                    self.scapyScan.daemon = True
                    # daemons get automatically closed when app exits
                    self.scapyScan.start()

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
                self.arpmodel.set_value(treeiter, 2, devicedesc)
                self.deviceDescList[mac] = devicedesc
                pickle.dump(self.deviceDescList, open("_devicelist.dict", "wb"))

        elif response == Gtk.ResponseType.CANCEL:
            print("Cancelled")
        dialog.destroy()

    def msg_dialog(self, title, message):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO,
                                   Gtk.ButtonsType.OK, title)
        dialog.format_secondary_text(message)
        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            print("OK")
        elif response == Gtk.ResponseType.CANCEL:
            print("Cancelled")
        dialog.destroy()
        self.jamStatus = False
        print('Stopped')

    def jam_loop(self, xhwdst, xpdst):
        xhwsrc = get_if_hwaddr(conf.iface)
        xpsrc = "192.168.1.1"
        #xhwsrc = "11:11:11:11:11:11:11:11"
        while self.jamStatus:
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + xpdst)
            packet = Ether()/ARP(op="who-has",hwsrc=xhwsrc, hwdst=xhwdst, psrc=xpsrc, pdst=xpdst)
            sendp(packet)
            x2pdst = "192.168.1.1"
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + x2pdst)
            packet = Ether()/ARP(op="who-has",hwsrc=xhwsrc, psrc=xpsrc, pdst=x2pdst)
            sendp(packet)
            x3pdst = "192.168.1.91"
            x3hwsrc = "11:11:11:11:11:11:11:11"
            print(xhwsrc + "/" + xpsrc + "-->" + xhwdst + "/" + x3pdst)
            packet = Ether()/ARP(op="who-has",hwsrc=x3hwsrc, psrc=xpsrc, pdst=xpdst)
            sendp(packet)
            time.sleep(.3)
            #print(bytes(response))
        return
    def ping_scan(self):


        inet = self.subnet.split(".")
        subnet = self.netmask.split(".")
        TIMEOUT = 2
        conf.verb = 0
        if int(subnet[2]) == 255:
            ip3range = [int(inet[2])]
        else:
            ip3range = range(0,255)
        ip4range = range(1,255)
        for ip3 in ip3range:
            for ip4 in ip4range:
                ip_dst = "192.168."+str(ip3)+"."+str(ip4)
                packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_dst)
                sendp(packet)
                #print('ARP '+ip_dst)
        return

    def port_scan(self, target_ip):
        print('Scan loop '+target_ip)
        scanList = [22,443,80,5900]

        scanned22 = self.port_scan_single(target_ip,22)
        scanned80 = self.port_scan_single(target_ip,80)
        scanned8080 = self.port_scan_single(target_ip,8080)
        scanned443 = self.port_scan_single(target_ip,443)
        scanned5900 = self.port_scan_single(target_ip,5900)
        scanned53 = self.port_scan_single(target_ip,53)

        if(scanned22 or scanned5900):
            print("LinuxLike")
        if(scanned80 or scanned443 or scanned8080 ):
            print("Webservice")
        if(scanned53 ):
            print("Gateway")

        return

    def port_scan_single(self, target_ip, port):
        dst_ip = target_ip
        src_port = RandShort()
        dst_port = port

        try:

            stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=10)
            if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
                print("Filtered")
                return None
            elif (stealth_scan_resp.haslayer(TCP)):
                if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), timeout=10)
                print("Open"+str(port))
                return True
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                print ("Closed"+str(port))
                return False
            elif (stealth_scan_resp.haslayer(ICMP)):
                if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and
                    int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    print ("Filtered"+str(port))
                    return None
        except:
            print("Error"+str(port))
            return False
        return False

win = MainWindow()
win.connect("destroy", win.on_MainWindow_deleted)
win.show_all()
Gtk.main()
