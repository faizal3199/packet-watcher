from scapy.all import *
from daemonize import Daemonize
import threading,ipcAPI,config,time,logging

class serviceProvider(object):
    """ Service handler class. Contains all objects """
    objList = None
    daemonObj = None

    def __init__(self):
        """ Init all objects and init handlers """

        self.services = [self.communication_handler]
        self.handlers = [self.handle_datalink,self.handle_networklayer,self.handle_transportlayer,self.handle_dns]

        self.daemonObj = Daemonize(app=config.APP_NAME, pid=config.PID_FILE, action=self.start_app_service)

    def main(self):
        """ Start the daemon service """
        self.daemonObj.start()

    def start_app_service(self):
        """ Main function to handle everything """

        self.init_logger() # logger in self.logger

        self.init_objects()

        self.logger.info("Starting service...")
        self.start_services()

        self.start_sniffing()

    def start_sniffing(self):
        """ Starts sniffing """
        self.logger.info("Starting sniffer...")
        try:
            sniff(iface='docker0',store=False,prn=self.packet_handler)
        except Exception as e:
            self.logger.error(e)

    def start_services(self):
        for service in self.services:
            t = threading.Thread(target=service)
            t.start()

    def unit_communication_handler(self,conn):
        """ Handles communication for each connection """
        cmd = conn.recv_data()
        feature = cmd['feature']
        args = cmd['args']

        self.logger.debug("Recivied commands: {} {}".format(feature,args))

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

    def init_logger(self):
        """ Creates logger object """
        fmt = "[%(asctime)s] %(module)s : <%(levelname)s> %(message)s"

        self.logger = logging.getLogger(config.APP_NAME)

        tempHandler = logging.FileHandler(config.LOG_FILE, "a")
        tempHandler.setLevel(logging.DEBUG)
        formatHandler = logging.Formatter(fmt,datefmt='%Y-%m-%d %H:%M:%S')
        tempHandler.setFormatter(formatHandler)

        self.logger.addHandler(tempHandler)
        # self.keep_fds = [self.logger.root.handlers[0].stream.fileno()]

    def init_objects(self):
        """ Init all objects in the objList"""

        from features.dnsBlocker import dnsBlocker
        from features.dataLinkLayer import dataLinkLayer
        from features.networkLayer import networkLayer
        from features.transportLayer import transportLayer

        self.objList = {
        'dataLinkLayer':{
                'obj': dataLinkLayer([],self.logger),#[(0,'BLOCK','*','docker0')]),
                'rules':[]
            },
        'networkLayer':{
            'obj': networkLayer([],self.logger),#[(0,'BLOCK','icmp')]),
            'rules':[]
            },
        'transportLayer':{
            'obj': transportLayer([],self.logger),#[(0,'BLOCK','*','*','*','7596')]),
            'rules':[]
            },
        'dnsBlocker':{
            'obj': dnsBlocker([],self.logger),#[(0,'BLOCK','*.blockme.com')]),
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
    serviceObj.start_app_service()
