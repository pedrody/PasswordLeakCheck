import argparse
import requests
import hashlib

# ANSI colors
RESET_COLOR = '\033[0m'
RED_COLOR = '\033[31m'
GREEN_COLOR = '\033[32m'
YELLOW_COLOR = '\033[93m'


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

    # Calculates the SHA-1 hash of the password and converts it to uppercase
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Separate the hash into prefix (first 5 characters) and suffix (rest)
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

    # Converts the password into hash prefix and suffix
    prefix, suffix = convert_password_to_hash(password)

    # Constructs the API URL based on the hash prefix
    url = f'https://api.pwnedpasswords.com/range/{prefix}'

    # Uncomment both prints if you want to view the prefix, suffix and URL.
    # print(f'{YELLOW_COLOR}PREFIX: {prefix} | SUFFIX: {suffix}{RESET_COLOR}')
    # print(f'{YELLOW_COLOR}URL: {url}{RESET_COLOR}\n')

    # Makes a GET request to the API
    response = requests.get(url)

    # If the requests is successful
    if response.status_code == 200:
        # Splits the response into lines and then splits each line into hash
        # and count
        hashes = (line.split(':') for line in response.text.splitlines())
        
        # Iterates over the returned hashes
        for h, count in hashes:
            # If the hash matches the password's hash suffix, returns the count
            if h == suffix:
                return int(count)
        # If the hash is not found, return 0 (not compromised)
        return 0
    
    else:
        # If the request fails, raises an exception with the status code
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
    
    # Reads passwords from the file
    with open(file, 'r') as f:
        passwords = f.read().splitlines()
    
    results = {}
    # For each password, checks if it has been compromised
    for password in passwords:
        count = check_password(password)
        # Stores the result (compromised or not) for each password
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

    # Setting up the parser to proccess command-line arguments
    parser = argparse.ArgumentParser(
        description='Check whether the password(s) provided have been leaked.'
        )
    
    # Argument to specify the passwords
    parser.add_argument(
        '-p',
        '--password',
        type=str,
        help='Password to be verified.'
    )

    # Argument to specify a file with passwords
    parser.add_argument(
        '-f', '--file', 
        type=str, 
        help='Path to the file with passwords.'
        )
    
    # Argument to save the results to a file
    parser.add_argument(
        '-sF', '--save-file', 
        type=str, 
        help='Path to save the file with the output information.'
    )
    args = parser.parse_args()

    # Checks if a password is provided
    if args.password:
        count = check_password(args.password)

        # If compromised, prints a warning message
        if count:
            print(f"{RED_COLOR}This password has been leaked {count} times."
                    f" It's recommended not to use it.{RESET_COLOR}")
        # If not compromised, prints a success message
        else:
            print(f'{GREEN_COLOR}The password was not found in the leaks. Good choice!{RESET_COLOR}')

    # Checks if a file of passwords is provided
    elif args.file and not args.save_file:
        results = check_password_from_file(args.file)
        # Prints the results for each password
        for password, status in results:
            color = GREEN_COLOR if status == 'Not Leaked' else RED_COLOR
            print(f'{color}Password: {password} | Status: {status}{RESET_COLOR}')
    
    # Checks if a file of passwords is provided and an output file is specified
    elif args.file and args.save_file:
        results = check_password_from_file(args.file)
        output_file = f'{args.save_file}.txt'

        # Saves the results to a file
        with open(output_file, 'a') as f:
            for password, result in results:
                f.write(f"{password}: {result}\n")
        
        # Prints a message informing where
        print(f'{YELLOW_COLOR}The results were saved in "{output_file}".{RESET_COLOR}')

if __name__ == '__main__':
    main()
