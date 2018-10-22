import re
from .baseClass import baseClass # .baseClass for denoting same directory

class transportLayer(baseClass):
    def __init__(self,rule_list = [],logger=print):
        """ Class to handle the transportLayer queries.
        rule_list should be a list of three tuple (time,'ALLOW|BLOCK',srcIP,srcPort,dstIP,dstPort) """

        super().__init__(rule_list,logger)

        return

    def get_port_by_service(self,service_name):
        """ Return port number for a service name """
        import socket
        service_name = service_name.lower()
        try:
            return str(socket.getservbyname(service_name))
        except:
            raise BaseException("Service not found. Use a well known service name.")

    def get_service_by_port(self,port):
        """ Return service name for a port number"""
        import socket
        port = int(port)
        try:
            return socket.getservbyname(port).upper()
        except:
            return "UNKOWN"

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list """

        def ip_to_regex(ip):
            """ Convert ip to regexs """
            ip = ip.replace('*','[\d.]*')
            ip = ip.replace('.','\.')
            ip = '^' + ip + '$' #Add start and end of line to prevent matched in substring
            return ip

        def port_to_regex(port):
            """ Convert port to regex. Also supports PORT name by service """
            if port == '*': # a regex convert to machine regex
                return '^[\d]*$'
            elif port.isdigit(): # Perfet value needed
                return '^'+port+'$'
            else: # A service name
                return '^'+str(self.get_port_by_service(port))+'$'

        regex_list = []

        for entry_time,entry_status,entry_srcip,entry_srcport,entry_dstip,entry_dstport in new_list:
            # Convert all IPs
            entry_srcip = ip_to_regex(entry_srcip)
            entry_dstip = ip_to_regex(entry_dstip)

            try:
                entry_srcport =  port_to_regex(entry_srcport)
                entry_dstport =  port_to_regex(entry_dstport)
            except:
                raise BaseException("Service name used is not found in general list. Please check")

            regex_list.append((entry_time,entry_status,entry_srcip,entry_srcport,entry_dstip,entry_dstport))

        return regex_list

    def handler(self,packet):
        """ handles a specific transportLayer query. Decides for blockage and log's message. Returns True if blocked else False """

        packet = packet.getlayer('IP')

        try:
            srcip = packet.src
            srcport = str(packet.sport)
            dstip = packet.dst
            dstport = str(packet.dport)
        except AttributeError as e:
            # No port found for the packet
            return False


        if self.is_blocked(srcip,srcport,dstip,dstport):
            message = "Found blocked port and IP combination: "
            message += "{}:{} to {}:{}".format(srcip,srcport,dstip,dstport)
            self.logger(message)
            return True
        return False

    def is_blocked(self,srcip,srcport,dstip,dstport):
        """ Performs regex check against a combination. True if blocked """
        # As the list gets sorted when saved. The last entry will be the final answer decider

        # RULE_LIST: (time,status,srcip,srcport,dstip,dstport)
        #               0       1       2   3       4       5

        def match_ip_and_port(rule,combination):
            """ Returns true if combination matches """
            if re.match(rule[0], combination[0], re.I|re.M): #Match IP
                if re.match(rule[1], combination[1], re.I|re.M): #Match port
                    return True
            return False

        length = len(self.RULE_LIST)

        for index in range(0,length):
            curr = length - 1 - index

            if match_ip_and_port(self.RULE_LIST[curr][2:4],(srcip,srcport)):
                if match_ip_and_port(self.RULE_LIST[curr][4:],(dstip,dstport)):
                    if self.RULE_LIST[curr][1] == 'BLOCK':
                        return True
                    else: # Latest entry allows to pass it
                        return False
        return False

# For testing purpose
# Intialize own object and provide it to global space
TEST_LIST = [(0,'BLOCK','*','*','172.17.0.2','80')]
transportLayerObj = transportLayer(TEST_LIST)
