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

if __name__ == '__main__':
    ...
