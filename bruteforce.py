#!/usr/bin/env python

import string
import optparse
import hashlib
import sys

hashing_algos = {32:"MD5", 40:"SHA1", 64:"SHA256"}


def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-p", "--pwd-hash", dest="pwd_hash", help="Hash of the password to bruteforce")
    #parser.add_option("-l", "--lowercase", action="store_true", dest="lowercase", help="Plain password may contain lowercase characters")
    parser.add_option("-u", "--uppercase", action="store_true", dest="uppercase", help="Plain password may contain uppercase characters")
    parser.add_option("-d", "--digits", action="store_true", dest="digits", help="Plain password may contain digits")
    parser.add_option("-s", "--special", action="store_true", dest="special", help="Plain password may contain special characters")
    parser.add_option("--length", dest="length", help="Plain password's length")
    parser.add_option("-a", "--all", action="store_true", dest="all", help="Use this option if you have no prior knowledge on the plain password")

    (options, arguments) = parser.parse_args()

    if not options.pwd_hash:
        parser.error("Please inset a hash, use --help for more info")

    return options


def build_charset(options):
    if options.all:
        charset = string.ascii_letters
        charset+=string.digits
        charset+=string.punctuation
        return charset
    charset = string.ascii_lowercase
    if options.uppercase:
        charset+=string.ascii_uppercase
    if options.digits:
        charset+=string.digits
    if options.special:
        charset+=string.punctuation
    return charset


def similar_hash(attempt, pwd_hash):
    if len(pwd_hash) == 32:
        m = hashlib.md5
    elif len(pwd_hash) == 40:
        m = hashlib.sha1
    elif len(pwd_hash) == 64:
        m = hashlib.sha256

    # if attempt == "dddd":
    #     print("attempt : {0}".format(attempt))
    #     print("m(attempt).hexdigest() : {0}".format(m(str(attempt)).hexdigest()))
    #     print("pwd_hash : {0}".format(pwd_hash))
    #     raw_input("OK")

    if m(attempt).hexdigest() == pwd_hash:
        return True
    else:
        return False


def bruteforce(attempt, position, size, pwd_hash, charset):
    # print(" ** size : {0}".format(size))
    # print(" ** position : {0}".format(position))
    # print(" ** charset : {0}".format(charset))
    # print(" ** charset[0] : {0}".format(charset[0]))
    new_attempt = attempt
    if position < size:
        for i in range(len(charset)):
            new_attempt = attempt
            new_attempt += charset[i]
            bruteforce(new_attempt, position+1, size, pwd_hash, charset)
    else:
        print("[+] Testing with : {0}".format(new_attempt))
        if similar_hash(new_attempt, pwd_hash):
            #print("Found : {0}".format(new_attempt))
            sys.exit("Found : {0}".format(new_attempt))


def main():
    options = get_arguments()
    charset = build_charset(options)
    print("Charset : {0}".format(charset))

    print("options.length : {0}".format(options.length))
    print("options.pwd_hash : {0}".format(options.pwd_hash))

    if options.length:
        bruteforce("", 0, int(options.length), options.pwd_hash, charset)
    else:
        for i in range(1, 10):
            bruteforce("", 0, i, options.pwd_hash, charset)


if __name__ == "__main__":
    main()
