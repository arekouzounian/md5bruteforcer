import hashlib    #used to generate md5 hashes
import itertools  #used to generate all possible passwords of a given alphabet 
import datetime   #used to timestamp findings of passwords
import os

#unnecessary. Just for a bit of added flair. 
ascii_art = '''
--------------------------------------------------------

    __  __           __    __                           
   / / / /___ ______/ /_  / /_  __  ______  ____  __  __
  / /_/ / __ `/ ___/ __ \/ __ \/ / / / __ \/ __ \/ / / /
 / __  / /_/ (__  ) / / / /_/ / /_/ / / / / / / / /_/ / 
/_/ /_/\__,_/____/_/ /_/_.___/\__,_/_/ /_/_/ /_/\__, /  
                                               /____/   

 -------------------------------------------------------
          Created by Arek Ouzounian for ITP125

'''

# this is our alphabet. It includes all upper and lowercase english letters, 
# as well as all base10 digits, and a good amount of special characters. 
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_"

# This function is utilized to generate all possible 
# combinations of characters of a given length (len), 
# within the given alphabet (in_str)
def cartesianProduct(len):
    yield from itertools.product(alphabet, repeat=len)

# This function takes in a string (in_str), and 
# returns the MD5 hash equivalent of that string. 
def hash(in_str):
    return hashlib.md5(in_str.encode()).hexdigest()

# This function combines the functionality of the previous two functions 
# and fully completes the process of bruteforcing. 
def main():
    os.system("clear")
    print(ascii_art) # just for fun

    # We begin by timestamping the process so that further 
    # password cracking has a chronological frame of reference.
    start = datetime.datetime.now()
    print("Cracking started at ", start)

    # Here, we grab the hashes from our file and dump them 
    # into a list object. 
    hashes = {}
    with open("hashes.txt") as f:
        for line in f.readlines():
            hashes.update({line.strip(): ""})

    # Here is the core loop. isDone is utilized to avoid 
    # extra work towards the end of cracking. 
    isDone = False
    # Looping through passwords of length 1 through 9
    # I could have made this an infinite loop, just increasingly
    # incrementing for larger and larger password sizes until
    # the hash list was empty, but I found that for the purpose
    # of this assignment, it was simpler to hard-code the password
    # lengths. Realistically speaking, most passwords fall between
    # 4 and 16 characters, so if this were to be applied to actual hashes, 
    # I would likely use a hard-coded range anyway. 
    for pass_len in range(1, 9):
        if not isDone:
            print("Started cracking", pass_len, "character passwords.")
            # looping through each individual password of length pass_len, as 
            # given by the cartesianProduct function 
            for pword in cartesianProduct(pass_len):
                #Escape case for end of hashing
                if len(hashes) < 1:
                    isDone = True
                    break

                # We convert our cartesian product tuple to a string, 
                # Hash the result, and compare it to our list of hashes.
                # If it matches, then we remove that hash from the list 
                # and document our progress. 
                strX = ''.join(pword)
                hsh = hash(strX)
                if hsh in hashes:
                    print("Hash:", hsh + " | Decoded: " + strX + " | Process completed in ", datetime.datetime.now() - start, "\n")
                    hashes.pop(hsh)  
    
    print('\n\nCongratulations! All passwords have been cracked. It took a grand total of: ' + datetime.datetime.now() - start)

main()
