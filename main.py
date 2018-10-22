import sys
from userHandler import userHandler

print('Firewall version 0.1')

args = sys.argv[1:]
userHandlerObj = userHandler()

if len(args) < 1 :
    userHandlerObj.print_help("Insufficient number of arguments")
    print('service [start|stop]')
    exit(1)

if args[0] == 'service':
    print('Service handlers to be implemented')
else:
    userHandlerObj.handle_user_input(args)
