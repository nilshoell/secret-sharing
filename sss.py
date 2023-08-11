#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# ------------------------- Shamir's Secret Sharing -------------------------
# sss.py
# Version: 0.2.1
# 2023-08-11
#
# Authors:
# Nils Höll
#
# ----------------------------------------------------------------------------
# This tool is a wrapper around the sample code Python implementation of Shamir's secret sharing
# released at https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing#Python_code
# under the CC0 and OWFa

import argparse
import base64
import math
import random
import functools
import os
import json
from hashlib import sha256

# ---------------------- CONFIG VARS ----------------------

# Program info
PROG_VERSION = "0.2.1"
PROG_DATE = "2023-08-11"
PROG_DESCRIPTION = """This tool is able to split a secret (e.g., a passphrase or key) into a user-defined number of shards based on Shamir's Secret Sharing algorithm.
To reconstruct the initial secret, only a subset of these shards is required (can also be specified).
NOTE: There is currently a length limitation for the secret, depending on its complexity, at around 12 chars."""

# Program defaults
TOTAL_SHARDS = 5
MIN_SHARDS = 3
SHARD_PATH = './shards'
DEBUG = False

# 12th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
_PRIME = 2 ** 127 - 1
# The 13th Mersenne Prime is 2**521 - 1

_RINT = functools.partial(random.SystemRandom().randint, 0)

# ------- Core Algorithm Functions -------

def _eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x, used to generate a
    shamir pool in make_random_shares below.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def make_random_shares(secret, minimum, shares, prime=_PRIME):
    """
    Generates a random shamir pool for a given secret, returns share points.
    """
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret] + [_RINT(prime - 1) for i in range(minimum - 1)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, shares + 1)]
    return points

def _extended_gcd(a, b):
    """
    Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1). This can
    be computed via the extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    """
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    """Compute num / den modulo prime p
    To explain this, the result will be such that: 
    den * _divmod(num, den, p) % p == num
    """
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x:int, x_s:tuple, y_s:tuple, p):
    """
    Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order.
    """
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"
    def PI(vals):  # upper-case PI -- product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

def recover_secret(shares:list, min:int, prime=_PRIME):
    """
    Recover the secret from share points
    (points (x,y) on the polynomial).
    """
    if len(shares) < min:
        raise ValueError(f"need at least {min} shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)


# ------- Helpers -------

# Converts a string into an integer represtation of its byte array
def secret_to_int(secret:str):

    # Convert to Base64 for predictable characters
    secret_b64 = base64.b64encode(secret.encode('utf-8'))

    # Convert into bitstring, with each character taking 7 bits
    secret_bin = ''.join(item[2:].zfill(7) for item in map(bin, secret_b64))

    # Convert to integer for SSS processing
    secret_int = int(secret_bin, 2)

    if DEBUG:
        print(f"[SPLIT]: Secret: {secret}")
        print(f"[SPLIT]: Secret b64: {secret_b64}")
        print(f"[SPLIT]: Secret bin: {secret_bin}")
        print(f"[SPLIT]: Secret int: {secret_int}")

    return secret_int


# Converts an integer back into a string
def int_to_secret(secret_int:int):
    secret_bin = bin(secret_int)[2:]
    secret_b64 = ""

    # Convert the bitstring back to Base 64
    for x in range(math.ceil(len(secret_bin) / 7)):
        char = int(secret_bin[x * 7:(x + 1) * 7], 2)
        secret_b64 += chr(char)
    
    if DEBUG:
        print(f"[JOIN]: Secret int: {secret_int}")
        print(f"[JOIN]: Secret bin: {secret_bin}")
        print(f"[JOIN]: Secret b64: {secret_b64}")
    
    # Decode the Base64 to the original secret
    secret = (base64.b64decode(secret_b64)).decode('utf-8')

    if DEBUG:
        print(f"[JOIN]: Secret: {secret}")
    
    return secret


# ------- Wrapper Functions -------

# Splits a secret into shards and saves those to files as JSON
def split_secret(secret:str, min:int, max:int):
    print(f"Splitting secret {secret}")
    secret_int = secret_to_int(secret)
    shards = make_random_shares(secret_int, minimum=min, shares=max)

    # Generate fingerprints
    fingerprints = []
    for shard in shards:
        id, value = shard
        fingerprint = sha256(f"{id}_{value}".encode()).hexdigest()[1:17]
        fingerprints.append(fingerprint)

    outfiles = []

    # Generate full objects and write them to files
    for shard in shards:
        id, value = shard
        fingerprint = sha256(f"{id}_{value}".encode()).hexdigest()[1:17]
        outfiles.append(f"{id}_{fingerprint}.json")

        # Dictionary that holds all relevant information for reconstruction & verification
        shard_obj = {
            'id': id,
            'shard': value,
            'fingerprint': fingerprint,
            'total_shards': max,
            'min_shards': min,
            'fingerprints': fingerprints
        }

        # Serializing as json
        json_object = json.dumps(shard_obj, indent=4)
 
        # Writing to json file
        with open(f"{SHARD_PATH}/{id}_{fingerprint}.json", "w") as outfile:
            outfile.write(json_object)

    return outfiles

# Takes a list of JSON files, parses them, and reconstructs the secret
def join_secrets(shard_files:list):

    shard_tuples = []

    # Check if files exist and parse them
    for file_path in shard_files:
        if not os.path.isfile(file_path):
            print(f"ERROR: Shard path '{file_path}' is not a file")
            return False
        
        with open(file_path) as f:

            # get values from file
            shard_obj = json.load(f)
            id = shard_obj['id']
            value = shard_obj['shard']
            fingerprint = shard_obj['fingerprint']
            min_shards = shard_obj['min_shards']

            if len(shard_files) < min_shards:
                print(f"ERROR: Number of supplied shards ({len(shard_files)}) is smaller than number of minimum shards ({min_shards})")
                return False

            # Check fingerprint
            fingerprint_new = sha256(f"{id}_{value}".encode()).hexdigest()[1:17]
            if fingerprint != fingerprint_new:
                print(f"ERROR: Fingerprint for shard #{id} not matching")
                return False
            
            # Build the tuple for further processing
            shard_tuples.append((id, value))

    # Reconstruct the original secret in its int represenation
    secret_int = recover_secret(shard_tuples, min_shards)
    secret = int_to_secret(secret_int)
    return secret


# ------- Main & Argparse -------

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=PROG_DESCRIPTION)
    parser.add_argument('--split', help='Split a secret (either given via -s or prompted on the cli) into shards. Takes -s, -n, and -m as arguments', action='store_true')
    parser.add_argument('--join', help='Join the given shard files back into the original secret. Takes multiple file paths.', nargs='+')
    parser.add_argument('-s', '--secret', help='The secret to split up')
    parser.add_argument('-n', '--num-shards', help='The total number of shards to generate', type=int, default=TOTAL_SHARDS)
    parser.add_argument('-m', '--min-shards', help='The minimum number of shards required to reconstruct the secret', type=int, default=MIN_SHARDS)
    parser.add_argument('-V', '--version', help='Print the version information', action='store_true')
    
    # Parse command line
    args = parser.parse_args()

    if args.version:
        print(PROG_DESCRIPTION)
        print("Version: " + str(PROG_VERSION) + " (" + str(PROG_DATE) + ")")
        exit()

    # Split the secret into shards
    if args.split:
        num_shards = args.num_shards
        min_shards = args.min_shards
        if not args.secret:
            secret = input("Please provide the secret to split:\n")
        else:
            secret = args.secret

        outfiles = split_secret(secret, min_shards, num_shards)

        if outfiles:
            print(f"The following {len(outfiles)} files have been generated:")
            for file in outfiles:
                print(file)
        else:
            print("ERROR: Could not generate shards/outfiles")
        
        return

    # Join the shards back into a secret
    if args.join:
        if type(args.join) != list or len(args.join) <= 1:
            print("ERROR: Please provide the path to at least two shard files")
            exit(1)

        shard_files = args.join
        
        result = join_secrets(shard_files)
        if result:
            print(f"The recovered secret is: {result}")
        else:
            print("ERROR: Reconstruction of secret not successful")
            exit(1)
        
        return

if __name__ == '__main__':
    main()