import argparse
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

def check_password_from_file(file):
    """
    The function `check_password_from_file` reads passwords from a file, checks if
    they have been leaked, and returns a dictionary with the passwords as keys and
    their leak status as values.
    
    :param file: The `file` parameter is the name or path of the file that contains
    a list of passwords
    :return: a list of tuples, where each tuple contains a password and its
    corresponding result.
    """
    with open(file, 'r') as f:
        passwords = f.read().splitlines()
    
    results = {}
    for password in passwords:
        count = check_password(password)
        if count:
            results[password] = f'Leaked {count} times'
        else:
            results[password] = 'Not Leaked'
    
    return results.items()

def main():
    """
    The main function checks whether a password or a file containing passwords have
    been leaked and provides the results either in the console or saves them in a
    file.
    """
    parser = argparse.ArgumentParser(
        description='Check whether the password(s) provided have been leaked.'
        )
    parser.add_argument(
        '-p',
        '--password',
        type=str,
        help='Password to be verified.'
    )
    parser.add_argument(
        '-f', '--file', 
        type=str, 
        help='Path to the file with passwords.'
        )
    parser.add_argument(
        '-sF', '--save-file', 
        type=str, 
        help='Path to save the file with the output information.'
    )
    args = parser.parse_args()

    if args.password:
        count = check_password(args.password)

        if count:
            print(f"This password has been leaked {count} times."
                    " It's recommended not to use it.")
        else:
            print('The password was not found in the leaks. Good choice!')

    elif args.file and not args.save_file:
        results = check_password_from_file(args.file)
        for password, status in results:
            print(f'Password: {password}  Status: {status}')
    
    elif args.file and args.save_file:
        results = check_password_from_file(args.file)
        output_file = f'{args.save_file}.txt'

        with open(output_file, 'a') as f:
            for password, result in results:
                f.write(f"{password}: {result}\n")
        
        print(f'The results were saved in "{output_file}".')


if __name__ == '__main__':
    main()
