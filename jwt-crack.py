import argparse
import base64
import json
import os
import sys
import jwt
from tqdm import tqdm


class ArgParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(usage='py /path/to/jwt_crack.py --decode --crack -w /path/to/wordlist.txt '
                                               '--token your.token.here -t 4',
                                         description='Script that helps you decode, encode and crack JWT tokens with simple secret')
        self.parser.add_argument('-d', '--decode', dest='decode', action='store_true', help='Prints decoded JWT token')

        self.parser.add_argument('-e', '--encode', dest='encode', action='store_true', help='Gets payload and private key, '
                                                                                       'then creates a new JWT-token')

        self.parser.add_argument('-c', '--crack', dest='crack', action='store_true', help='Cracks JWT-token and prints '
                                                                                     'it\'s secret if found, use it with -d parameter')

        self.parser.add_argument('-w', '--wordlist', action='store', dest='wordlist', type=str, help='Wordlist',
                            default='./jwt.secrets.list')

        self.parser.add_argument('--token', action='store', dest='token', type=str, help='Your JWT-token', default=None)

        self.parser.add_argument('--header', action='store', dest='header', type=str,
                                 help='Your JWT-token', default=None)

        self.parser.add_argument('-p', '--payload', action='store', dest='payload', type=str,
                            help='Payload you want to modify', default=None)

        self.parser.add_argument('-k', '--key', action='store', dest='key', type=str,
                            help='Secret key needed to create JWT-token', default=None)

        self.parser.add_argument('-a', '--algorithm', action='store', dest='algorithm', type=str,
                            help='Algorithm for jwt', default=None)

        self.args = self.parser.parse_args()
        self.check_args()

    def raise_error(self, message):
        print(message)
        self.parser.print_help()
        sys.exit()

    def check_args(self):
        if not self.args.decode and not self.args.encode and not self.args.crack:
            self.raise_error('Select type of operation')
        if self.args.crack or self.args.decode:
            if self.args.token is None:
                self.raise_error('Enter Jwt-token')


class CrackHandler:
    def __init__(self, arguments=None):
        self.args = arguments
        self.token = self.args.token
        self.header = self.args.header
        self.payload = self.args.payload
        self.signature = None
        self.secret = self.args.key

        self.decode_token()
        if self.args.crack:
            self.crack_token()
        if self.args.encode:
            if self.secret is not None and self.payload is not None and (self.header is not None
                                                                         or self.args.algorithm is not None):
                token = self.encode_token()
                print('----------------------------------\n'
                      f'Your Token : \n{token}\n'
                      '----------------------------------')
            else:
                print('Secret key is missing')
                sys.exit()

    def decode_token(self):
        try:
            jwt_token = self.args.token.split(sep='.', maxsplit=3)
            decoded_token = []
            for i in range(0, 2):
                part = jwt_token[i] + '=='
                part_bytes = base64.b64decode(part)
                decoded_part = part_bytes.decode("ascii")
                decoded_token.append(decoded_part)

            self.header = json.loads(decoded_token[0])
            self.payload = json.loads(decoded_token[1])
            self.signature = jwt_token[2]
            self.token = f'{jwt_token[0]}.{jwt_token[1]}.{jwt_token[2]}'

            if self.args.decode:
                self.print_token()
        except Exception as e:
            print(f'JWT token incorrect: {e}')
            sys.exit()

    def print_token(self):
        print('----------------------------------\n'
              'Decoded JWT-token:\n'
              f'Headers: {self.header}\n'
              f'Payload: {self.payload}\n'
              f'Signature: {self.signature}\n'
              '----------------------------------')

    def encode_token(self):
        payload = self.payload if self.args.payload is None else self.args.payload
        header = self.header if self.args.header is None else self.args.header
        secret = self.secret if self.args.key is None else self.args.key
        algorithm = self.args.algorithm

        if not isinstance(payload, dict):
            payload = json.loads(payload.replace('\'', '\"'))
        if not isinstance(header, dict):
            header = json.loads(header.replace('\'', '\"'))

        try:
            if algorithm is None:
                encoded_data = jwt.encode(payload=payload, key=secret, headers=header)
            else:
                encoded_data = jwt.encode(payload=payload, key=None, algorithm=algorithm) \
                    if algorithm == "none" else jwt.encode(payload=payload, key=secret, algorithm=algorithm)
            return encoded_data
        except Exception as e:
            print(f'Payload, header or algorithm incorrect: {e}')
            return None

    def create_token(self, key):
        try:
            encoded_data = jwt.encode(payload=self.payload, key=key, headers=self.header)
            return encoded_data
        except Exception as e:
            print(f'Payload or header incorrect: {e}')
            return None

    def crack_token(self):
        data = self.read_file_if_exists(self.args.wordlist)
        if isinstance(data, str):
            print(data)
            sys.exit()
        else:
            print('Cracking:')
            iterator = tqdm(data, leave=False)
            for key in iterator:
                token = self.create_token(key)
                if token == self.token and isinstance(token, str):
                    print(f'\nSecret key for yor token: \n{key.decode('utf-8')}\n'
                          '----------------------------------')
                    self.secret = key
                    iterator.close()
                    return
            print('No secret key found')

    def read_file_if_exists(self, file_path):
        if os.path.isfile(file_path):
            try:
                with open(file_path, 'rb') as file:
                    content = file.read().splitlines()
                    return content
            except Exception as e:
                return f"Error in opening wordlist: {e}"
        else:
            return "Path to dictionary incorrect"


if __name__ == '__main__':
    parser = ArgParser()
    jwt_crack = CrackHandler(arguments=parser.args)
