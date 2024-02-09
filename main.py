import requests
import hashlib


def convert_password_to_hash(password):
    """
    The function `convert_password_to_hash` takes a password as input, converts it
    to a SHA-1 hash, and returns the hash split into a prefix and suffix.
    
    :param password: The `password` parameter is the string that you want to convert
    to a hash
    :return: a tuple containing two strings. The first string is the prefix, which
    is the first 5 characters of the SHA-1 hash of the password. The second string
    is the suffix, which is the remaining characters of the SHA-1 hash of the
    password.
    """
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    return prefix, suffix


def check_password(password):
    """
    The `check_password` function checks if a given password has been compromised by
    querying the Pwned Passwords API.
    
    :param password: The `password` parameter is a string that represents the
    password that needs to be checked
    :return: The function `check_password` returns an integer value representing the
    number of times the given password has been found in breached password
    databases.
    """
    prefix, suffix = convert_password_to_hash(password)

    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    response = requests.get(url)

    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    
    else:
        response.raise_for_status()

if __name__ == '__main__':
    ...
