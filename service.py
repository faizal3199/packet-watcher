from scapy.all import *
import threading,ipcAPI,config,time

class serviceProvider(object):
    """ Service handler class. Contains all objects """
    objList = None
    daemonObj = None

    def __init__(self):
        """ Init all objects and init handlers """
        self.init_objects()

        self.services = [self.communication_handler]
        self.handlers = [self.handle_datalink,self.handle_networklayer,self.handle_transportlayer,self.handle_dns]

    def start_sniffing(self):
        """ Starts services and sniffing """
        print("Starting service...")
        self.start_services()

        print("Starting sniffer...")
        try:
            sniff(iface='docker0',store=False,prn=self.packet_handler)
        except Exception as e:
            print(e)
        print("Exiting...")

    def start_services(self):
        for service in self.services:
            t = threading.Thread(target=service)
            t.start()

    def unit_communication_handler(self,conn):
        """ Handles communication for each connection """
        cmd = conn.recv_data()
        feature = cmd['feature']
        args = cmd['args']

        if feature == 'service':
            if args[0] == 'stop':
                conn.send_data({'status':'Success','message':'Stoping daemon service'})
                self.daemonObj.exit()
        else:
            args = (time.time(),args[0].upper()) + args[1:] # Capitalize BLOCK or ALLOW
            try:
                self.rule_updater_for_single_obj(feature,args)
            except Exception as e:
                conn.send_data({'status':'Error','message':e.args[0]})
                conn.close()
                return False
            conn.send_data({'status':'Success','message':'Update successfull.'})
            conn.close()
            return True
        return True

    def rule_updater_for_single_obj(self,layer,new_rules):
        """ Handles the rules updation for a single a layer. Handles all errors and replies"""
        new_list = self.objList[layer]['rules'].copy()

        new_list.append(new_rules)

        self.objList[layer]['obj'].update_list(new_list)

        return True

    def communication_handler(self):
        """ Blocking listener function. Calls unit_communication_handler for each connection"""
        self.serverObj = ipcAPI.ipcServer(config.SOCKET_FILE)

        self.serverObj.start_listening(self.unit_communication_handler)

    def init_objects(self):
        """ Init all objects in the objList"""

        from features.dnsBlocker import dnsBlocker
        from features.dataLinkLayer import dataLinkLayer
        from features.networkLayer import networkLayer
        from features.transportLayer import transportLayer

        self.objList = {
        'dataLinkLayer':{
                'obj': dataLinkLayer(),#[(0,'BLOCK','*','docker0')]),
                'rules':[]
            },
        'networkLayer':{
            'obj': networkLayer(),#[(0,'BLOCK','icmp')]),
            'rules':[]
            },
        'transportLayer':{
            'obj': transportLayer(),#[(0,'BLOCK','*','*','*','7596')]),
            'rules':[]
            },
        'dnsBlocker':{
            'obj': dnsBlocker(),#[(0,'BLOCK','*.blockme.com')]),
            'rules':[]
            },
        }

        return True

    def packet_handler(self,packet):
        """ Callback function for scapy """
        for handler_function in self.handlers:
            t = threading.Thread(target=handler_function,args=(packet,))
            t.start()

    def handle_datalink(self,packet):
        """ Handler for dataLinkLayer """
        if packet.haslayer('Ether'):
            self.objList['dataLinkLayer']['obj'].handler(packet)
            return True
        return False

    def handle_networklayer(self,packet):
        """ Handler for networkLayer """
        if packet.haslayer('IP'):
            self.objList['networkLayer']['obj'].handler(packet)
            return True
        return False

    def handle_transportlayer(self,packet):
        """ Handler for transportLayer """
        if packet.haslayer('IP'):
            self.objList['transportLayer']['obj'].handler(packet)
            return True
        return False

    def handle_dns(self,packet):
        """ Handler applicationLayer(DNS) """
        if packet.haslayer('DNS'):
            self.objList['dnsBlocker']['obj'].handler(packet)
            return True
        return False

if __name__ == "__main__":
    serviceObj = serviceProvider()
    serviceObj.start_sniffing()
