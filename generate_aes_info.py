import os
import sys


def main():
    # Generate AES key file
    key_file = open('key.bin', 'wb')
    key_file.write(os.urandom(32))
    key_file.close()

    # Generate AES iv file in order to use CBC mode
    iv_file = open('iv.bin', 'wb')
    iv_file.write(os.urandom(16))
    iv_file.close()


if __name__ == '__main__':
    if len(sys.argv) != 1:
        print('Additional command line arguments are unnecessary to run this program.')
        exit()

    main()
