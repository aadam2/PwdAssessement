#!/usr/bin/env python

import string
import optparse
import operator

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

def flatten(l):
    flat_list = [item for sublist in l for item in sublist]
    return flat_list

def build_charset(options):
    if options.all:
        charset = list(string.ascii_letters)
        charset.append(list(string.digits))
        charset.append(list(string.punctuation))
        return flatten(charset)
    charset = list(string.ascii_lowercase)
    if options.uppercase:
        charset.append(list(string.ascii_uppercase))
    if options.digits:
        charset.append(list(string.digits))
    if options.special:
        charset.append(list(string.punctuation))
    return flatten(charset)

def main():

    options = get_arguments()
    charset = build_charset(options)
    print("charset : {0}".format(charset))

if __name__ == "__main__":
    main()