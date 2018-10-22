import socket,threading,struct

class baseIpcClass(object):
    def __init__(self,sockObj):
        self.sockObj = sockObj

    def encode(self,obj):
        """ encode to a string. obj should be json serializable """
        import yaml
        return bytes(yaml.dump(obj),'utf-8')

    def decode(self,data):
        """ decode data to json object """
        import yaml
        return yaml.load(data.decode('utf-8'))

    def send_data(self,data):
        """ Sends data to the sockObj """
        try:
            data = self.encode(data)
        except:
            raise BaseException("Invalid data type for encoding")
            return False
        try:
            # Put metadata of size ahead of the real data
            # It supports upto 3.99 GB data so no worry about fragmentation
            # Provides supports for message-based protocol
            data = struct.pack('>I',len(data)) + data
            self.sockObj.send(data)
        except:
            raise BaseException("Can't send data over conenction")
            return False

        return True

    def recv_data(self):
        """ Recvs data over conenction. Also decode and returns data """
        data = ""
        size = 0

        try:
            size = self.sockObj.recv(4) #Get metadata
        except:
            raise BaseException("Error while receiving data. Probably broken pipe")

        if len(size) == 0:
            raise BaseException("No data recivied. Probably broken pipe")

        size = struct.unpack('>I',size)[0]

        data = self.sockObj.recv(size)

        if len(data) != size:
            raise BaseException("Partiala data recivied")

        return self.decode(data)

    def __delete__(self):
        self.sockObj.close()

class ipcServer(object):
    def __init__(self,sockFileName):
        """ Init a server socket. Socket not ready for listening """
        import os
        self.sockObj = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)

        self.serverAddress = sockFileName

        try:
            if os.path.exists(self.serverAddress):
                os.unlink(self.serverAddress)
            self.sockObj.bind(self.serverAddress)
        except:
            raise BaseException("Address already in use. {}".format(self.serverAddress))

    def start_listening(self,callback_function,client_count=1):
        """Blockin function. Callback function must accept baseIpcClass object.
        callback_function called every time a conn is recivied."""
        self.sockObj.listen(client_count)

        try:
            while True:
                conn,addr = self.sockObj.accept()
                obj = baseIpcClass(conn)
                t = threading.Thread(target=callback_function,args=(obj,))
                t.start()
        except:
            pass # Generated during the server socket closing

    def __delete__(self):
        self.sockObj.close()

class ipcClient(baseIpcClass):
    def __init__(self,sockFileName):
        """ Init a client socket"""
        import os
        self.sockObj = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)

        self.serverAddress = sockFileName

        try:
            self.sockObj.connect(self.serverAddress)
        except:
            raise BaseException("Cann't connect to address")

    def __delete__(self):
        self.sockObj.close()
