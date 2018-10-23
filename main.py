import sys,os
from userHandler import userHandler
import config,ipcAPI

def handle_service(args):
    if len(args) < 1:
        print("Usage:")
        print("service [start|stop]")
        exit(1)

    if args[0] == 'start':
        if os.path.exists(config.PID_FILE):
            print("The service is already running. Check PID file at {}".format(config.PID_FILE))
            exit(1)
        else:
            import service
            service.main()
    elif args[0] == "stop":
        if not os.path.exists(config.PID_FILE):
            print("The service is not running. Check PID file at {}".format(config.PID_FILE))
            exit(1)
        else:
            client = ipcAPI.ipcClient(config.SOCKET_FILE)
            client.send_data({'feature':'service','args':('stop')})

            resp = client.recv_data()
            print("{} : {}".format(resp['status'],resp['message']))
    else:
        print("Usage:")
        print("service [start|stop]")
        exit(1)

if __name__=='__main__':
    print('{} {}'.format(config.APP_NAME,config.APP_VERSION))

    args = sys.argv[1:]
    userHandlerObj = userHandler()

    if len(args) < 1 or (len(args) >=1 and args[0] == 'help'):
        userHandlerObj.print_help("Help docs...")
        print('service [start|stop]')
        exit(1)

    if os.getuid() != 0:
        print("Tool requires root access to run. Please provide root access")
        exit(1)

    if args[0] == 'service':
        handle_service(args[1:])
    else:
        userHandlerObj.handle_user_input(args)
