import socket

HOST = '35.185.50.240'  # The server's hostname or IP address
PORT = 30330            # The port used by the server

def main():
    """
    Sends a 'Hello World!' message to our server using a TCP socket.

    Creates a TCP socket, connects to the server, sends a message, receives the echo result,
    and then prints the response.

    Parameters
    ----------
    void : void type
        No parameters used

    Returns
    -------
    void
        Nothing of values is returned

    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b'Hello World!') # Send 'Hello World!' to server
        data = s.recv(1024)

    print('Received', repr(data))


if __name__ == '__main__':
    main()
