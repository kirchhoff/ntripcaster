#-*- encoding=utf-8 -*-
__author__ = 'kirchhoff'
from ConfigParser import ConfigParser
import base64
import socket
import time
import threading
User_auth={}
SERVER_IP=""
PORT=0
SOURCE_PASSWD=""
SOURCE_BINDS={}
SOCKET_BINDS={}
class MY_ConfigParser(ConfigParser):
    '''
    使用 configParser过程，发现他对option的大小写不敏感，全部变成小写
    重载optionxform方法，返回optionstr，原来是return optionstr.lower()
    '''
    def optionxform(self, optionstr):
        return optionstr

def caster_configparser(file_path):
    global User_auth
    global SERVER_IP
    global PORT
    global SOURCE_PASSWD
    config = MY_ConfigParser()
    config.read(file_path)
    opts = config.options("user_config")
    for i in opts:
        user_passwd=config.get("user_config", i)
        User_auth[i]=user_passwd
    print "User auth is ",User_auth
    SERVER_IP = config.get("server_network_config", 'server_name')
    PORT = int(config.get("server_network_config", "port"))
    SOURCE_PASSWD = config.get("source_passwd", "password")

def handle(sk):
    global SOURCE_PASSWD
    global User_auth
    data = sk.recv(1024)
    data = str(data)
    if data.startswith("GET"):
        try:
            data=data.replace("\r\n"," ")
            print "$$%r$$" %data
            l=data.split(" ")
            mountpoint=l[1]
            if mountpoint.startswith("/"):
                mountpoint=mountpoint[1:]
            try:
                auth_index = l.index("Authorization:")
            except ValueError:
                sk.send(bytes("HTTP/1.0 401 Unauthorized"))
                sk.close()
                return
            if User_auth.has_key(mountpoint) == False:#
                sk.send(bytes("SORCETABLE 200 OK"))
                sk.close()
                return
            try:
                if l[auth_index+1]=="Basic":
                    s=str(base64.b64decode(l[auth_index+2]))
                    print s
                    if User_auth[mountpoint] == s:#认证完毕
                        print "auth success"
                        print "mountpoint is %s" % mountpoint
                        if SOURCE_BINDS.has_key(mountpoint) == False:#不存在source
                            print "no mountpoint"
                            sk.send(bytes("can't get request data"))
                            sk.close()
                            return
                        else:
                            sk.send(bytes("ICY 200 OK\r\n"))
                            SOCKET_BINDS[mountpoint].append(sk)
            except TypeError:
                sk.send(bytes("HTTP/1.0 401 Unauthorized"))
                sk.close()
            finally:
                pass
        finally:
            pass

    elif data.startswith("SOURCE"):
        try:
            data=data.replace("\r\n"," ")
            print "##%r##" % data
            l=data.split(" ")
            mountpoint=l[2]
            if mountpoint.startswith("/"):
                mountpoint=mountpoint[1:]
            print "mountpoint is %s"% mountpoint
            if l[1] == SOURCE_PASSWD and SOURCE_BINDS.has_key(mountpoint) == False and User_auth.has_key(mountpoint) == True:
                print "ICY 200 OK\n"
                sk.send(bytes("ICY 200 OK\r\n"))
                SOURCE_BINDS[mountpoint]=None
                SOCKET_BINDS[mountpoint]=[]
                while 1:
                    SOURCE_BINDS[mountpoint]=sk.recv(1024)
                    if len(SOURCE_BINDS[mountpoint]) == 0:
                        SOURCE_BINDS.pop(mountpoint)
                        print "source has terminate the connection"
                        sk.close
                        for i in SOCKET_BINDS[mountpoint]:
                            try:
                                i.send(bytes("can't request the data"))
                                i.close()
                            except Exception:
                                SOCKET_BINDS[mountpoint].remove(i)
                        SOCKET_BINDS.pop(mountpoint)
                        break
                    for i in SOCKET_BINDS[mountpoint]:
                        try:
                            i.send(bytes(SOURCE_BINDS[mountpoint]))
                        except Exception:
                            SOCKET_BINDS[mountpoint].remove(i)
                print "outer\n"
                if SOURCE_BINDS.has_key(mountpoint):
                    SOURCE_BINDS.pop(mountpoint)
                sk.close
                return
            elif l[1] == SOURCE_PASSWD and SOURCE_BINDS.has_key(mountpoint) == True:#密码正确，但是已存在mountpoint
                sk.send(bytes("mountpoint has been taken"))
                sk.close
            elif l[1] != SOURCE_PASSWD:#密码不正确
                sk.send(bytes("ERROR-Bad Password"))
                sk.close
            else:#mountpoint不在配置文件中
                sk.send(bytes("can't ac mountpoint"))
                sk.close
        finally:
            pass
    else:
        sk.send(bytes("HTTP/1.0 400 Bad Request\r\nServer: NTRIP NtripCaster\r\nContent-Type: text/html\r\nConnection: close\r\n"))


def show_BINDS():
    global SOURCE_BINDS
    while 1:
        time.sleep(1)
        print "source binds is ",SOURCE_BINDS
        print "socket binds is ",SOCKET_BINDS

def init_server():
    global SERVER_IP
    global PORT
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind((SERVER_IP,PORT))
    print "waiting for connection..."
    threading.Thread(target=show_BINDS).start()
    s.listen(5)
    while 1:
        clientsock,clientaddr =s.accept()
        threading.Thread(target=handle,args=(clientsock,)).start()

if __name__ == "__main__":
    caster_configparser("/Users/kirchhoff/caster.conf")
    init_server()

