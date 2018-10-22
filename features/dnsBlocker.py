import re

class dnsBlocker(object):
    BLOCKED_LIST = []

    def __init__(self,block_list = [],logger=print):
        """ Class to handle the DNS queries """

        self.logger = logger

        if type(block_list) == type(self.BLOCKED_LIST):
            self.BLOCKED_LIST = self.convert_list(block_list)
            self.BLOCKED_LIST.sort()
        else:
            raise TypeError("Got {} expected {}".format(type(block_list),type(self.BLOCKED_LIST)))

        # self.logger(self.BLOCKED_LIST)

        return

    def update_list(self,new_list):
        """ Updates current block list with new passed one. new_list should be a list of three tuple (time,'ALLOW|BLOCK',domain) """
        if type(new_list) == type(self.BLOCKED_LIST):
            self.BLOCKED_LIST = self.convert_list(new_list)
            self.BLOCKED_LIST.sort()
            return True
        else:
            raise TypeError("Got {} expected {}".format(type(new_list),type(self.BLOCKED_LIST)))
            return False

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list """

        regex_list = []

        for entry_time,entry_status,entry_domain in new_list:
            # Make domain name satisfy FQDN pattern
            if not entry_domain.endswith('.'):
                entry_domain = entry_domain + '.'

            # Convert human understanable regex to machine understanable
            entry_domain = entry_domain.replace('*','[\w-]*')
            entry_domain = entry_domain.replace('.','\.')
            entry_domain = '^' + entry_domain + '$' #Add start and end of line to prevent matched in substring

            regex_list.append((entry_time,entry_status,entry_domain))

        return regex_list

    def handler(self,packet):
        """ handles a specific DNS query. Decides for blockage and self.loggers message. Returns True if blocked else False """

         # Check using flag's first bit. If 1 then response. If 0 the query
        if packet.getlayer('DNS').qr == 0:
            queried_domain = packet.getlayer('DNS').qd.qname.decode('utf-8')

            # self.logger("Got DNS query: {}".format(queried_domain))

            if self.is_domain_blocked(queried_domain):
                self.logger('Found blocked domain: {}'.format(queried_domain))
                return True
        return False

    def is_domain_blocked(self,domain):
        """ Performs regex check against a domain. True if blocked """

        # As the list gets sorted when saved. The last entry will be the final answer decider

        # BLOCKED_LIST: (time,status,domain)
        length = len(self.BLOCKED_LIST)

        for index in range(0,length):
            if re.match(self.BLOCKED_LIST[length-1-index][2], domain, re.I|re.M) != None: # Domain is present in our list
                if self.BLOCKED_LIST[length-1-index][1] == 'BLOCK':
                    return True
                else: # Latest entry allows to pass it
                    return False
        return False

# For testing purpose
# Intialize own object and provide it to global space
TEST_LIST = [(0,'BLOCK','*.blockme.com')]
dnsBlockerObj = dnsBlocker(TEST_LIST)
