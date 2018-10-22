class baseClass(object):
    RULE_LIST = []

    def __init__(self,block_list = [],logger=print):
        """ Class to handle the queries (baseClass)"""

        self.logger = logger

        if type(block_list) == type(self.RULE_LIST):
            self.RULE_LIST = self.convert_list(block_list)
            self.RULE_LIST.sort()
            self.RULE_LIST.reverse()
        else:
            raise TypeError("Got {} expected {}".format(type(block_list),type(self.RULE_LIST)))

        # self.logger(self.RULE_LIST)

        return

    def update_list(self,new_list):
        """ Updates current block list with new passed one"""
        if type(new_list) == type(self.RULE_LIST):
            self.RULE_LIST = self.convert_list(new_list)
            self.RULE_LIST.sort()
            self.RULE_LIST.reverse()
            return True
        else:
            raise TypeError("Got {} expected {}".format(type(new_list),type(self.RULE_LIST)))
            return False

    def convert_list(self,new_list):
        """ Convert the passed list into a regex list. Implemnt owns """
        raise NotImplementedError("Implemnt in child class")

    def handler(self,packet):
        """ handles a specific query. Decides for blockage and self.loggers message. Returns True if blocked else False """
        raise NotImplementedError("Implemnt in child class")

    def is_blocked(self,args):
        """ Performs checks against passed args. return True if blocked """
        raise NotImplementedError("Implemnt in child class")
