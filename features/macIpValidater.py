class macIpValidater(object):
    BROADCAST_MAC = ['ff:ff:ff:ff:ff:ff']
    ZERO_MAC = ['00:00:00:00:00:00']

    CONGEST_CONTROL_SETTING = False # Block packet that congest network. True: on . False: off

    def __init__(self,packet,allowed_mapping):
        """ dns_packet is high level DNS packet from scapy """

        if len(allowed_mapping) == 0:
            raise BaseException("Allowed mapping list is empty")
            return

        self.src_ip = packet.getlayer('IP').src
        self.src_mac = packet.getlayer('Ether').src
        self.dst_mac = packet.getlayer('Ether').dst

        self.IP_FOR_MAC = allowed_mapping.get(self.src_mac)

        if not self.decide_allowed_packets():
            print("Invalid mapping found. '{}' to '{}'".format(self.src_ip,self.src_mac))
            return

    def mac_is_gratiuos(self,mac):
        if mac == self.BROADCAST_MAC or mac == self.ZERO_MAC:
            return True
        return False

    def decide_allowed_packets(self):
        # block packets with confusing origin. rarelly possible
        if self.mac_is_gratiuos(self.src_mac):
            return False

        # CONGEST_CONTROL_SETTING
        if self.CONGEST_CONTROL_SETTING and self.mac_is_gratiuos(self.dst_mac):
            return False

        if self.IP_FOR_MAC == None: # Mapping not found
            return False
        if self.IP_FOR_MAC == self.src_ip:
            return True
        return False
