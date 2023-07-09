import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import argparse
import sys
import tqdm
import xml.etree.ElementTree as ET


def decrypt_legacy(encrypted_data, password, bruteforce):
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data = base64.b64decode(encrypted_data)
        initial_vector = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        key = hashlib.md5(password.encode()).digest()

        cipher = AES.new(key, AES.MODE_CBC, initial_vector)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception as e:
        if(bruteforce == False):
            print("Failed to decrypt the password with the following error: {}".format(e))
        return b''

def decrypt(encrypted_data, password, bruteforce):
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        key = hashlib.pbkdf2_hmac(
            "sha1", password.encode(), salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        if(bruteforce == False):
            print("Failed to decrypt the password with the following error: {}".format(e))
        return b''


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt mRemoteNG passwords.")
    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", help="Name of file containing encrypted mRemoteNG password")
    group.add_argument("-rf", "--realFile", help="Name of dumped mRemoteNG connection file containing the encrpyted password")
    group.add_argument("-s", "--string", help="base64 string of mRemoteNG password")
    parser.add_argument("-p", "--password", help="Custom decryption password", default="mR3m")
    parser.add_argument("-L", "--legacy", help="version <= 1.74", type=bool, default=False)
    parser.add_argument("-b", "--bruteforce", help="Try to bruteforce custom mRemoteNG decryption password. Use in combination with with -s option", type=bool, default=False)
    parser.add_argument("-w", "--wordlist", help="Name of wordlist to use for bruteforce")
    args = parser.parse_args()

    decrypt_func = decrypt
    if args.legacy:
        decrypt_func = decrypt_legacy

    if args.realFile != None:
        tree = ET.parse(args.realFile)
        root = tree.getroot()
        for node in root.iter('Node'):
            if node.attrib['Password']:
                decPass = decrypt_func(node.attrib['Password'], args.password, args.bruteforce)
                if node.attrib['Username']:
                    print("Username: {}".format(node.attrib['Username']))
                if node.attrib['Hostname']:
                    print("Hostname: {}".format(node.attrib['Hostname']))
                if node.attrib['Password']:
                    print("Encrypted Password: {} ".format(node.attrib['Password']))
                print("Decrpyted Password: {} \n".format(decPass.decode("utf-8")))
        sys.exit(1)

    elif args.file != None:
        with open(args.file) as f:
            encrypted_data = f.read()
            decPass = decrypt(encrypted_data, args.password,args.bruteforce)

    elif args.string != None:
        if args.bruteforce and args.wordlist != None:
            encrypted_data = args.string
            num_lines = sum(1 for line in open(args.wordlist,'r'))
            with open(args.wordlist, "r") as wordlist:
                print("Total entries in wordlist:", num_lines)
                pbar = tqdm.tqdm(total=num_lines, desc='Progress')
                for password in (wordlist):
                    pbar.update(1)
                    decPass = decrypt(encrypted_data, password.replace("\n", ""),args.bruteforce)
                    if(decPass.decode("utf-8") != ''):
                        print("\n Decryption password found: ", password)
                        print("\n Decrypted: {}".format(decPass.decode("utf-8")))
                        sys.exit(1)
                print("No passwords found")
                sys.exit(1)
        if args.bruteforce and args.wordlist == None:
            print("Please define a wordlist to use for bruteforce with (-w, --wordlist) flag")
            sys.exit(1)
        else:    
            encrypted_data = args.string
            decPass = decrypt(encrypted_data, args.password,args.bruteforce)

    else:
        print("Please define either file containing encrypted mRemoteNG password (-f, --file) or password string (-s, --string) flag")
        sys.exit(1)

    try:
        print("Password: {}".format(decPass.decode("utf-8")))
    except Exception as e:
        print("Failed to find the password property with the following error: {}".format(e))

if __name__ == "__main__":
    main()