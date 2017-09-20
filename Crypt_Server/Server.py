import socket
from multiprocessing import Manager

import Crypt_Server.Crypt as Crypt
from Crypto.Random import get_random_bytes


class KeyExchangeFailed(Exception):

    def __init__(self, *args):
        super().__init__(*args)


class Server:

    def __init__(self, ip, port, claves=None, bits=4096, unhandled_connections=5):
        """
        Set ups the server and generate the keys
        :param ip: Ip to bind
        :param port: Port to bind
        :param claves: Cryptographic keys to use(if None, it'll generate them)
        :param bits: Bits for generating the keys(These keys should be stronger than the client ones because is 
        your public key which provides the tunnel for the other key to travel and are the same across all the 
        clients)
        :param unhandled_connections: Number of non-accepted connections before starting refusing them
        """
        if claves is None:
            self.claves = Crypt.generate(bits)
        else:
            self.claves = claves
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((ip, port))
        self.s.listen(unhandled_connections)

    def accept(self, timeout=None):
        self.s.settimeout(timeout)
        conn, addr = self.s.accept()
        return conn

    def key_exchange(self, conn, timeout=None, tunnel_anchor=1024 * 1024, token_size=32):
        """
        Accept a connection(this should be iterated to avoid unhandled connections)
        :param conn: Connection to handle
        :param timeout: Time to wait for a connection
        :param tunnel_anchor: Bits anchor for the key exchange
        :param token_size: Authentication token size to generate
        :raise KeyExchangeFailed
        :return: Connnection object or Timeout Exception if timeout met
        """
        conn.settimeout(timeout)
        try:
            conn.send(self.claves["PUBLIC"])
            public = Crypt.decrypt(conn.recv(tunnel_anchor), self.claves["PRIVATE"]).decode()
            server_token = get_random_bytes(token_size)
            conn.send(Crypt.encrypt(server_token, public))
            token = Crypt.decrypt(conn.recv(tunnel_anchor), self.claves["PRIVATE"])
        except:
            conn.close()
            raise KeyExchangeFailed("The key exchange failed. Connection closed")
        connection = Connection(conn, public, token, self.claves["PRIVATE"], server_token)
        return connection

    def __del__(self):
        self.s.close()


class InvalidToken(Exception):

    def __init__(self, *args):
        super().__init__(*args)


class DisconnectedClient(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class UnableToDecrypt(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class Connection:

    def __init__(self, conn, public, client_token, private, server_token):
        """
        Connection object handling cryptography and authentication methods
        :param conn: Socket connection object
        :param public: Public key of the client
        :param client_token: Authentication token of the client
        :param private: Private key of the server
        :param server_token: Authentication token of the server
        """
        self.conn = conn
        self.public = public
        self.client_token = client_token
        self.private = private
        self.server_token = server_token
        manager = Manager()
        self.blocked = manager.Value(bool, False)

    def close(self):
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.conn.close()

    def send(self, msg, number_size=5):
        """
        Sends the given data to the client
        :param msg: Message to send(String)
        :param number_size: Size in bytes of integer representing the size of the message
        :raise DisconnectedClient
        :return: VOID
        """
        msg = self.server_token + msg.encode()
        msg = Crypt.encrypt(msg, self.public)
        leng = len(msg).to_bytes(number_size, "big")
        try:
            self.conn.send(leng)
            self.conn.send(msg)
        except socket.error:
            self.close()
            raise DisconnectedClient("The client has been disconnected. Connection closed")

    def recv(self, timeout=None, number_size=5):
        """
        Receives data from the client and check the token
        :param timeout: Time to wait until exiting
        :param number_size: Size in bytes of integer representing the size of the message
        :raise UnableToDecrypt
        :raise DisconnectedClient
        :raise InvalidToken
        :return: Message received(String)
        """
        self.conn.settimeout(timeout)
        long = int.from_bytes(self.conn.recv(number_size), "big")
        try:
            msg = self.conn.recv(long)
        except socket.error:
            self.close()
            raise DisconnectedClient("The client has been disconnected. Connection closed")
        if msg == b"":
            self.close()
            raise DisconnectedClient("The client has been disconnected. Connection closed")
        try:
            msg = Crypt.decrypt(msg, self.private)
        except:
            self.close()
            raise UnableToDecrypt("Unable to decrypt the client message")
        if self.client_token in msg:
            msg = msg.replace(self.client_token, b"", 1)
        else:
            raise InvalidToken("The token provided by the client doesn't match the original one. Maybe an attempt"
                               "of man-in-the-middle?")
        return msg.decode()

    def get_conn(self):
        """
        Gets the Connection object from the socket module(This object should only be used to gather information
        of the client such as getting the address, never to send or receive directly as it would break the 
        protocol)
        :return: Connection Socket's object
        """
        return self.conn

if __name__ == "__main__":
    server = Server("localhost", 8001)
    con = server.accept()
    con.send("HOLA")
    # print(con.recv())
    con.close()
    while True: pass
