import re

class dataLinkLayer(object):
    RULE_LIST = []

    def __init__(self,rule_list = [],logger=print):
        """ Class to handle the dalaLinkLayer queries """

        self.logger = logger
        if type(rule_list) == type(self.RULE_LIST):
            self.RULE_LIST = self.convert_list(rule_list)
            self.RULE_LIST.sort()
        else:
            raise TypeError("Got {} expected {}".format(type(rule_list),type(self.RULE_LIST)))

        # self.logger(self.RULE_LIST)

        return

    def getHardwareAddress(self,ifname):
        """ Get MAC address of a interface """
        import fcntl, socket, struct
        ifname = ifname.encode('utf-8')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        except IOError as e:
            return None

        return ':'.join(['%02x' % char for char in info[18:24]])

    def update_list(self,new_list):
        """ Updates current rule list with new passed one. new_list should be a list of tuple (time,'ALLOW|BLOCK',srcMAC|ifname,dstMAC|ifname) """
        if type(new_list) == type(self.RULE_LIST):
            self.RULE_LIST = self.convert_list(new_list)
            self.RULE_LIST.sort()
            return True
        else:
            raise TypeError("Got {} expected {}".format(type(new_list),type(self.RULE_LIST)))
            return False

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list """
        import re

        mac_verify_regex = "^(?:[0-9A-F]{2}[:-]){5}(?:[0-9A-F]{2})$"
        regex_list = []

        for entry_time,entry_status,entry_src,entry_dst in new_list:
            # check if src is proper mac address if not convert to mac
            if not re.match(mac_verify_regex,entry_src,re.I):# Must be an interface name or regex
                if entry_src != '*':
                    entry_src = self.getHardwareAddress(entry_src)

            # check if dst is proper mac address if not convert to mac
            if not re.match(mac_verify_regex,entry_dst,re.I):# Must be an interface name or regex
                if entry_dst != '*':
                    entry_dst = self.getHardwareAddress(entry_dst)

            if not entry_src or not entry_dst: #Maybe interface name's weren't valid
                continue

            # Convert human understanable regex to machine understanable
            entry_src = entry_src.replace('*',mac_verify_regex)
            entry_dst = entry_dst.replace('*',mac_verify_regex)

            regex_list.append((entry_time,entry_status,entry_src,entry_dst))

        return regex_list

    def handler(self,packet):
        """ handles a specific dataLinkLayer query. Decides for blockage and log message. Returns True if blocked else False """


        hw_addr_src = packet.getlayer('Ether').src
        hw_addr_dst = packet.getlayer('Ether').dst

        if self.is_blocked(hw_addr_src,hw_addr_dst):
            self.logger('Found blocked dataLinkLayer packet: {} to {}'.format(hw_addr_src,hw_addr_dst))
            return True
        return False

    def is_blocked(self,src,dst):
        """ Performs regex check against a combination. True if blocked """
        # RULE_LIST: (time,status,src,dst)
        #               0   1       2   3
        length = len(self.RULE_LIST)

        for index in range(0,length):
            if re.match(self.RULE_LIST[length-1-index][2], src, re.I|re.M): # src is present in our list
                if re.match(self.RULE_LIST[length-1-index][3], dst, re.I|re.M): # dst is present in our list
                    if self.RULE_LIST[length-1-index][1] == 'BLOCK':
                        return True
                    else: # Latest entry allows to pass it
                        return False
        return False # No combination found

# For testing purpose
# Intialize own object and provide it to global space
TEST_LIST = [(0,'BLOCK','docker0','*')]
dataLinkLayerObj = dataLinkLayer(TEST_LIST)
