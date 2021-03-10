import socket

HOST = '0.0.0.0'    # Listen from any IP
PORT = 30330        # Port to listen on (non-privileged ports are > 1023)

def main():
    """
    Echos a 'Hello World!' message back to the client using a TCP socket

    Creates a TCP socket, binds it to a specific port, listens for client connections, prints the IP of
    the connected client, and then echos the received message back to the client.

    Parameters
    ----------
    void : void type
        No parameters used

    Returns
    -------
    void
        Nothing of value is returned

    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print('Received: ', repr(data))
                conn.sendall(data)  # Send 'Hello World!' back


if __name__ == '__main__':
    main()
