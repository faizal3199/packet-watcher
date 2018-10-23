import re
from .baseClass import baseClass # .baseClass for denoting same directory

class dnsBlocker(baseClass):
    def __init__(self,rule_list = [],logger=print):
        """ Class to handle the DNS queries.
        rule_list should be a list of three tuple (time,'ALLOW|BLOCK',domain)"""

        super().__init__(rule_list,logger)

        return

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list """

        regex_list = []

        for entry_time,entry_status,entry_domain in new_list:
            entry_status = entry_status.upper()

            if not entry_status == 'ALLOW' and not entry_status == 'BLOCK':
                raise Exception("Blockage status shall be ALLOW or BLOCK")

            # Make domain name satisfy FQDN pattern
            if not entry_domain.endswith('.'):
                entry_domain = entry_domain + '.'

            # Convert human understanable regex to machine understanable
            entry_domain = entry_domain.replace('*','[\w-]*')
            entry_domain = entry_domain.replace('.','\.')
            entry_domain = '^' + entry_domain + '$' #Add start and end of line to prevent matched in substring

            self.logger.info("New rule added: ({}, {})".format(entry_status,entry_domain))
            regex_list.append((entry_time,entry_status,entry_domain))

        return regex_list

    def handler(self,packet):
        """ handles a specific DNS query. Decides for blockage and self.loggers message. Returns True if blocked else False """

         # Check using flag's first bit. If 1 then response. If 0 the query
        if packet.getlayer('DNS').qr == 0:
            queried_domain = packet.getlayer('DNS').qd.qname.decode('utf-8')

            # self.logger("Got DNS query: {}".format(queried_domain))

            if self.is_blocked(queried_domain):
                self.logger.warning('Found blocked domain: {}'.format(queried_domain))
                return True
        return False

    def is_blocked(self,domain):
        """ Performs regex check against a domain. True if blocked """

        # As the list gets sorted when saved. The last entry will be the final answer decider

        # RULE_LIST: (time,status,domain)

        for index in range(0,len(self.RULE_LIST)):
            if re.match(self.RULE_LIST[index][2], domain, re.I|re.M) != None: # Domain is present in our list
                if self.RULE_LIST[index][1] == 'BLOCK':
                    return True
                else: # Latest entry allows to pass it
                    return False
        return False

# For testing purpose
# Intialize own object and provide it to global space
TEST_LIST = [(0,'BLOCK','*.blockme.com')]
dnsBlockerObj = dnsBlocker(TEST_LIST)
