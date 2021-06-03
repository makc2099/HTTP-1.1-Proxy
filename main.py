import os
import sys
import _thread
import socket
import time
import json

BLACKLIST = []
ForbiddenMSG = b'\r\n'.join([
    b'HTTP/1.1 403',
    b'Server: proxy',
    b'Content-type: text/html\r\n',
    b'<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>403 Access Denied</H1><p>You don\'t have permission to access on this server.</p></BODY></HTML>'])
CACHE = {}


def prepare():
    # getting list of blocked websites
    global BLACKLIST, CACHE
    try:
        with open("blacklist.conf") as f:
            BLACKLIST = f.readlines()
    except:
        pass
    BLACKLIST = [x.strip() for x in BLACKLIST]

def create_proxy_socket(host, port):
    # creating server socket
    print("Proxy Server " + host + ":" + str(port))
    prepare()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen(100)
    except socket.error:
        if s:
            s.close()
        print("Can not open proxy socket")
        sys.exit(1)
    return s


def my_send(s, msg):
    # send data + check if send completely
    MSGLEN = len(msg)
    totalsent = 0
    while totalsent < MSGLEN:
        sent = s.send(msg[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent = totalsent + sent


def my_recv(s, timeout=0.3):
    #recieving packets ensuring that no packets are lost
    total_data = []
    data = b''
    #wait for first message then open recv
    s.setblocking(1)
    try:
        data = s.recv(8192)
    except:
        pass
    if data:
        total_data.append(data)
    else:
        return b''

    #if time between packets > 0.3 => close connection
    s.setblocking(0)
    begin = time.time()
    while 1:
        if (time.time() - begin) > timeout:
            break
        try:
            data = s.recv(8192)
            if data:
                total_data.append(data)
                begin = time.time()
            else:
                time.sleep(0.1)
        except:
            pass
    s.setblocking(1)
    return b''.join(total_data)


def parser_request(server_name, server_port, msg):
    #parsing request packet
    max_age = 300
    request = msg.split(b'\r\n\r\n')
    request_header = request[0]
    request_header = request_header.split(b'\r\n')
    method = request_header[0].decode()
    if not server_name:

        host = request_header[4].decode()
        # domain name
        server_name = host.split(" ")[-1]
        # port
        port_position = server_name.find(":")
        # default port 80
        if port_position == -1:
            server_port = 80
        else:
            server_port = int(server_name[port_position + 1:])
            server_name = server_name[:port_position]

    for i in range(2, len(request_header)):
        if len(request_header[i]) < 50:
            if b'ache-Control:' in request_header[i]:
                p_age = request_header[i].find(b'max-age')
                if p_age != -1:
                    p_temp = request_header[i][p_age:].split(b' ')[0]
                    max_age = int(p_temp[8:])
                    break

                if b'no-store' in request_header[i] or \
                        b'no-cache' in request_header[i] or \
                        b'private' in request_header[i]:
                    max_age = 0
                    break
    return server_name, server_port, method, max_age


def parser_respond(msg, max_age):
    #parse respond
    connection = False
    respond = msg.split(b'\r\n\r\n')
    respond_header = respond[0]
    respond_header = respond_header.split(b'\r\n')

    for i in range(1, len(respond_header)):
        if len(respond_header[i]) < 25:
            if b'onnection:' in respond_header[i]:
                if b'keep-alive' in respond_header[i]:
                    connection = True
                break

    for i in range(1, len(respond_header)):
        if len(respond_header[i]) < 50:
            if b'ache-Control:' in respond_header[i]:
                p_age = respond_header[i].find(b'max-age')
                if p_age != -1:
                    p_temp = respond_header[i][p_age:].split(b' ')[0]
                    max_age = int(p_temp[8:])
                    break

                if b'no-store' in respond_header[i] or \
                        b'no-cache' in respond_header[i] or \
                        b'private' in respond_header[i]:
                    max_age = 0
                    break
    return connection, max_age


def blacklist(client_socket, client_address, server_name, method):
    # check if blacklisted
    for i in range(len(BLACKLIST)):
        if BLACKLIST[i] in server_name:
            print("BLOCK", client_address, method)
            client_socket.send(ForbiddenMSG)
            return False
    return True


def cache(file_name, respond, max_age, connection):
    # save file_name in CACHE dictionary
    global CACHE
    CACHE[file_name] = [respond, time.time() + max_age, connection]


def fetch(file_name):
    #finds respond package with file_name
    global CACHE
    respond = b''
    connection = False
    cache_status = -1
    if file_name[0:3] == 'GET':
        full_respond = CACHE.get(file_name)

        if full_respond:
            age = full_respond[1]
            # resend respond only when file name is found in CACHE and lifetime is greater than current time
            if age > time.time():
                respond = full_respond[0]
                connection = full_respond[2]
                cache_status = 1
            else:
                cache_status = 0
        else:
            cache_status = 0
    return respond, cache_status, connection


def proxy(client_socket, client_address):
    first_step = True
    server_socket = None
    connection = True
    server_name = ''
    server_port = 80
    while connection:
        request = my_recv(client_socket)
        if not request:
            break
        # request parsing, max_age for caching
        server_name, server_port, method, max_age = parser_request(server_name, server_port, request)
        # create file name to find this file in proxy cache
        file_name = ','.join([method, server_name, str(server_port)])
        print(client_address, method)
        # searches for files in proxy cache, returns cache_status = (1-cache hit, 0-cache miss, -1-no cache)
        respond, cache_status, connection = fetch(file_name)
        # cache hit, return response to client
        if cache_status == 1:
            my_send(client_socket, respond)
            print("RESPOND", '[proxy_cache]', client_address)
            connection, max_age = parser_respond(respond, max_age)
            continue
        # if first connection - proxy connects to socket server
        if first_step:
            if blacklist(client_socket, client_address, server_name, method):
                try:
                    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if method[:7] == 'CONNECT':
                        proxy_https(client_socket, server_socket, server_port, server_name)
                    server_socket.connect((server_name, server_port))
                except:
                    break
            else:
                break
            first_step = False
        # cache miss or no-cache, go to the server to request the packet
        my_send(server_socket, request)
        respond = my_recv(server_socket)
        my_send(client_socket, respond)
        print("RESPOND", '[', server_name, ':', server_port, ']', client_address)

        connection, max_age = parser_respond(respond, max_age)
        # if it's cache-miss and not no-cache, save a copy of the respond packet
        if cache_status == 0:
            cache(file_name, respond, max_age, connection)
    if server_socket:
        server_socket.close()
    if client_socket:
        client_socket.close()

def proxy_https(client_socket,server_socket, server_port, server_name):
    try:
        server_socket.connect((server_name, server_port))
        reply = "HTTP/1.1 200 Connection established\r\n"
        reply += "ProxyServer-agent: PyProxyServer\r\n\r\n"
        client_socket.sendall(reply.encode())
    except socket.error as err:
        print(err)
    client_socket.setblocking(False)
    server_socket.setblocking(False)

    while True:
        try:
            data = client_socket.recv(8192)
            if not data:
                client_socket.close()
                break
            server_socket.sendall(data)
        except socket.error:
            pass

        try:
            reply = server_socket.recv(8192)
            if not reply:
                server_socket.close()
                break
            client_socket.sendall(reply)
        except socket.error:
            pass

def main():
    s = create_proxy_socket('127.0.0.1', 8888)
    # accept connections from client, for each connection -> create a separate processing thread
    while 1:
        try:
            client_socket, client_address = s.accept()
            _thread.start_new_thread(proxy, (client_socket, client_address))
        except KeyboardInterrupt:
            s.close()
            sys.exit(0)
    s.close()


if __name__ == '__main__':
    main()
