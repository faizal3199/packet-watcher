from .baseClass import baseClass # .baseClass for denoting same directory

class networkLayer(baseClass):
    def __init__(self,rule_list = [],logger=print):
        """ Class to handle the networkLayer queries.
        rule_list should be a list of tuple (time,'ALLOW|BLOCK',protocol) """

        self.populate_table()

        super().__init__(rule_list,logger)

        return

    def populate_table(self):
        """ Populate the proto_table with name:number """
        import socket
        self.proto_table = {name[8:]:num for name,num in vars(socket).items() if name.startswith("IPPROTO")}
        return True

    def getProtocolNumber(self,proto_name):
        """ Provide protocol number against it's name """
        return self.proto_table.get(proto_name)

    def getProtocolName(self,proto_number):
        """ provide protocol name for it's number"""
        for name,num in self.proto_table.items():
            if num == proto_number:
                return name
        return "UNKNOWN"

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list """
        regex_list = []

        for entry_time,entry_status,entry_protocol in new_list:
            # convert protocols by name to numbers
            if not entry_protocol.isdigit():# Must be an name
                entry_protocol = self.getProtocolNumber(entry_protocol.upper())

            if not entry_protocol: # passed value wasn't valid
                continue

            regex_list.append((entry_time,entry_status,entry_protocol))

        return regex_list

    def handler(self,packet):
        """ handles a specific networkLayer query. Decides for blockage and log message. Returns True if blocked else False """

        packet = packet.getlayer('IP')

        proto_number = packet.proto

        if self.is_blocked(proto_number):
            self.logger('Found blocked protocol {}: {} to {}'.format(self.getProtocolName(proto_number),packet.src,packet.dst))
            return True
        return False

    def is_blocked(self,proto_number):
        """ Performs check against a protocol. True if blocked """
        # RULE_LIST: (time,status,protocol)
        #               0   1       2
        length = len(self.RULE_LIST)

        for index in range(0,length):
            if self.RULE_LIST[length-1-index][2] == proto_number:
                if self.RULE_LIST[length-1-index][1] == 'BLOCK':
                    return True
                else: # Latest entry allows to pass it
                    return False
        return False # No data found

# For testing purpose
# Intialize own object and provide it to global space
TEST_LIST = [(0,'BLOCK','icmp')]
networkLayerObj = networkLayer(TEST_LIST)
