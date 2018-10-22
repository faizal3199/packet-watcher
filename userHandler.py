class userHandler(object):
    """ Handels user queries related to features """

    def __init__(self):
        """ Sets help message """
        self.help_message = {
            'dataLinkLayer':"[ALLOW|BLOCK] [srcMAC|ifname] [dstMAC|ifname]",
            'networkLayer':"[ALLOW|BLOCK] [tarsport-layer-protocol]",
            'transportLayer':"[ALLOW|BLOCK] [srcIP] [srcPort] [dstIP] [dstPort]",
            'dnsBlocker':"[ALLOW|BLOCK] [domain]"
            }
        return

    def datalink_args(self,args):
        """ Handler for dataLinkLayer """
        if len(args) != 3:
            self.print_help(msg="Invalid number of arguments",category="dataLinkLayer")
            exit(1)

        return tuple(args)

    def networklayer_args(self,args):
        """ Handler for networkLayer """
        if len(args) != 2:
            self.print_help(msg="Invalid number of arguments",category="networkLayer")
            exit(1)

        return tuple(args)

    def transportlayer_args(self,args):
        """ Handler for transportLayer """
        if len(args) != 5:
            self.print_help(msg="Invalid number of arguments",category="transportLayer")
            exit(1)

        return tuple(args)

    def dnsblocker_args(self,args):
        """ Handler for dnsBlocker """
        if len(args) != 2:
            self.print_help(msg="Invalid number of arguments",category="dnsBlocker")
            exit(1)

        return tuple(args)

    def get_message(self,args):
        """ Returns parsed message """
        if len(args) < 1:
            self.print_help(msg="Insufficient number of arguments")
            exit(1)

        if args[0] == 'dataLinkLayer':
            feature = 'dataLinkLayer'
            message_args = self.datalink_args(args[1:])
        elif args[0] == 'networkLayer':
            feature = 'networkLayer'
            message_args = self.networklayer_args(args[1:])
        elif args[0] == 'transportLayer':
            feature = 'transportLayer'
            message_args = self.transportlayer_args(args[1:])
        elif args[0] == 'dnsBlocker':
            feature = 'dnsBlocker'
            message_args = self.dnsblocker_args(args[1:])
        else:
            self.print_help()
            exit(1)

        message = {'feature':feature,
                    'args':message_args}

        return message

    def handle_user_input(self,args):
        """ Handles user message and communicates rules """
        import ipcAPI,config

        message = self.get_message(args)
        client = ipcAPI.ipcClient(config.SOCKET_FILE)

        client.send_data(message)

        resp = client.recv_data()

        print("{} : {}".format(resp['status'],resp['message']))

        return True


    def print_help(self,msg=None,category='all'):
        """ print help message for any category """
        if msg:
            print("Error: {}\n".format(msg))

        print("Usage:")
        if category == 'all':
            for x in self.help_message:
                print("{} {}".format(x,self.help_message[x]))
        else:
            print("{} {}".format(category,self.help_message[category]))

if __name__ == '__main__':
    import sys
    hanlderObj = userHandler()
    print(hanlderObj.get_message(sys.argv[1:]))
