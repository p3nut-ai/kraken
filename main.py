import hashlib
from urllib.request import urlopen
from colorama import Fore
import time


def crack_sha1():
    get_sha1_hash = input('[*] Enter sha1 hash: ')

    # get online password list
    online_pass_list  = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt').read(), 'utf-8')


    # loop thru online dict and compare
    for password in online_pass_list.split('\n'):
        # convert all password from list to sha1
        convert_to_sha1 = hashlib.sha1(bytes(password,'utf-8')).hexdigest()

        # compare password from list to the sha1 input

        if convert_to_sha1 == get_sha1_hash:
            print(Fore.GREEN + "[*] Password found: " + str(password))
            quit()
        else:
            print(Fore.RED + '[*] Password not match skip to the next one [*]')
            # if password is not in password list
    print(Fore.YELLOW + 'Password is not in the list')
def convert_to_sha1():
    get_password_to_be_hashed = input('[*] Enter password here: ')

    hash_type = hashlib.sha1()
    hash_type.update(get_password_to_be_hashed.encode()) # convert string to hash
    #
    print(Fore.GREEN + "Here's your sha1 hash password: " + hash_type.hexdigest()) #output hash

def convert_Sha256():
    get_password_to_be_hashed = input('[*] Enter password here: ')

    hash_type = hashlib.sha256()
    hash_type.update(get_password_to_be_hashed.encode()) # convert string to hash
    #
    print(Fore.GREEN + "Here's your Sha256 hash password: " + hash_type.hexdigest())
def crack_Sha256():

    get_sha256_hash = input('[*] Enter sha256 hash: ')
    # get online password list
    online_pass_list  = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt').read(), 'utf-8')


    # loop thru online dict and compare
    for password in online_pass_list.split('\n'):
        # convert all password from list to sha1
        convert_to_sha256 = hashlib.sha256(bytes(password,'utf-8')).hexdigest()

        # compare password from list to the sha1 input

        if get_sha256_hash == convert_to_sha256:
            print(Fore.GREEN + "[*] Password found: " + str(password))
            quit()
        else:
            print(Fore.RED + '[*] Password not match skip to the next one [*]')
            # if password is not in password list
    print(Fore.YELLOW + 'Password is not in the list')

def crack_md5():
    get_md5_hash = input('[*] Enter md5 hash: ')

    # get online password list
    online_pass_list  = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt').read(), 'utf-8')


    for password in online_pass_list.split('\n'):
        print(Fore.YELLOW + '[-] Trying: ' + password)

        # hashing all password to md5
        enc_password = password.encode('utf-8')
        password_md5 = hashlib.md5(enc_password).hexdigest()

        if password_md5 == get_md5_hash:
            print(Fore.GREEN + "[+] Password Found: " + password)
            quit()
    # if password is no in list
    print(Fore.YELLOW + 'Password is not in the list')
def convert_to_md5():
    get_password_to_be_hashed = input('[*] Enter password here: ')

    hash_type = hashlib.md5()
    hash_type.update(get_password_to_be_hashed.encode()) # convert string to hash
    #
    print(Fore.GREEN + "Here's your sha1 hash password: " + hash_type.hexdigest()) #output hash

def convert_sha512():
    get_password_to_be_hashed = input('[*] Enter password here: ')

    hash_type = hashlib.sha512()
    hash_type.update(get_password_to_be_hashed.encode()) # convert string to hash
    #
    print(Fore.GREEN + "Here's your Sha512 hash password: " + hash_type.hexdigest())
def crack_sha512():
    get_sha512_hash = input('[*] Enter sha512 hash: ')
    # get online password list
    online_pass_list  = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt').read(), 'utf-8')


    # loop thru online dict and compare
    for password in online_pass_list.split('\n'):
        # convert all password from list to sha1
        convert_to_sha512 = hashlib.sha512(bytes(password,'utf-8')).hexdigest()

        # compare password from list to the sha1 input

        if get_sha512_hash == convert_to_sha512:
            print(Fore.GREEN + "[*] Password found: " + str(password))
            quit()
        else:
            print(Fore.RED + '[*] Password not match skip to the next one [*]')

    print(Fore.YELLOW + 'Password is not in the list')



# ask if user want to convert pass to hash or crack hash
print(Fore.WHITE + '''
                    ------------------------------------
                     ..............
                   ::::::::::::::::::
                  :::::::::::::::
                 :::`::::::: :::     :
                 :::: ::::: :::::    :
                 :`   :::::;     :..~~
                 :   ::  :::.     :::.
                 :...`:, :::::...:::
                ::::::.  :::::::::'
                 ::::::::|::::::::  !
                 :;;;;;;;;;;;;;;;;']}      Password Hashing/Cracking
                 ;--.--.--.--.--.-
                  \/ \/ \/ \/ \/ \/               By: p3nut.
                     :::       ::::
                      :::      ::
                     :\:      ::
                   /\::    /\:::
                 ^.:^:.^^^::`::
                 ::::::::.::::
                  .::::::::::


                    (1) crack hash \n
                    (2) convert password to hash

                    ------------------------------------
                    ''')
ask_user = input(Fore.WHITE + '> ')

if ask_user == '1':

    # ask user what type of hash he got
    print(Fore.YELLOW + '''
        ***************************

        1) Sha1
        2) Sha256
        3) Md5
        4) Sha512

        ***************************
    ''')
    get_hash_type = input(Fore.CYAN + '[+] What type of hash password you want to crack? :')


    # check hash type
    if get_hash_type == '1':
        crack_sha1()
    elif get_hash_type == '2':
        crack_Sha256()
    elif get_hash_type == '3':
        crack_md5()
    elif get_hash_type == '4':
        crack_sha512()
    else:
        print(Fore.RED + "that's not in options ")

else:
    print(Fore.YELLOW + '''
        ***************************

        1) Sha1
        2) Sha256
        3) Md5
        4) Sha512

        ***************************
    ''')
    print(Fore.WHITE + 'What type of hash you want?')
    hash_pass_type = input('> ')

    if hash_pass_type == '1':
        convert_to_sha1()
    elif hash_pass_type == '2':
        convert_Sha256()
    elif hash_pass_type == '3':
        convert_to_md5()
    elif hash_pass_type == '4':
        convert_sha512()
    else:
        print(Fore.RED + "that's not in options " )
