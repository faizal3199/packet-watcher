#!/usr/bin/python3

import sys,os,time
from userHandler import userHandler
import config,ipcAPI
from signal import SIGTERM

def kill_service(pidfile):
    """
    Stop the daemon
    """
    # Get the pid from the pidfile
    try:
            pf = open(pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
    except IOError:
            pid = None

    if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            sys.stderr.write(message % pidfile)
            return # not an error in a restart

    # Try killing the daemon process
    try:
            while 1:
                    os.kill(pid, SIGTERM)
                    time.sleep(0.1)
    except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                    if os.path.exists(pidfile):
                            os.remove(pidfile)
            else:
                    print(str(err))
                    sys.exit(1)

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
            serviceObj = service.serviceProvider()
            serviceObj.main()
            print("Service started")
    elif args[0] == "stop":
        if not os.path.exists(config.PID_FILE):
            print("The service is not running. Check PID file at {}".format(config.PID_FILE))
            exit(1)
        else:
            kill_service(config.PID_FILE)
            # client = ipcAPI.ipcClient(config.SOCKET_FILE)
            # client.send_data({'feature':'service','args':('stop')})
            #
            # resp = client.recv_data()
            # print("{} : {}".format(resp['status'],resp['message']))
    else:
        print("Usage:")
        print("service [start|stop]")
        exit(1)

if __name__=='__main__':
    print('{} {}\n'.format(config.APP_NAME,config.APP_VERSION))

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
