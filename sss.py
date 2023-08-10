#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# ------------------------- Shamir's Secret Sharing -------------------------
# sss.py
# Version: 0.1.0
# 2023-08-10
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

# ---------------------- CONFIG VARS ----------------------

# Program info
prog_version = "0.1.0"
prog_date = "2023-08-10"
prog_description = ""

# Program defaults
TOTAL_SHARDS = 5
MIN_SHARDS = 3

# 12th Mersenne Prime
# (for this application we want a known prime number as close as
# possible to our security level; e.g.  desired security level of 128
# bits -- too large and all the ciphertext is large; too small and
# security is compromised)
_PRIME = 2 ** 127 - 1
# The 13th Mersenne Prime is 2**521 - 1

_RINT = functools.partial(random.SystemRandom().randint, 0)

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

def _lagrange_interpolate(x, x_s, y_s, p):
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

def recover_secret(shares, prime=_PRIME):
    """
    Recover the secret from share points
    (points (x,y) on the polynomial).
    """
    if len(shares) < 3:
        raise ValueError("need at least three shares")
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)

# Converts a string into an integer represtation of its byte array
def secret_to_int(secret:str):
    secret_b64 = base64.b64encode(secret.encode('utf-8'))
    secret_bin = ''.join(item[2:] for item in map(bin, secret_b64))
    secret_int = int(secret_bin, 2)
    return secret_int

# Converts an integer back into a string
def int_to_secret(secret_int:int):
    secret_bin = bin(secret_int)[2:]
    secret_b64 = ""
    for x in range(math.ceil(len(secret_bin) / 7)):
        char = int(secret_bin[x * 7:(x + 1) * 7], 2)
        secret_b64 += chr(char)
    secret = (base64.b64decode(secret_b64)).decode('utf-8')
    return secret

def split_secret(secret:str, min:int, max:int):
    secret_int = secret_to_int(secret)
    shards = make_random_shares(secret_int, minimum=min, shares=max)
    return shards

def join_secrets(shard_files:list):
    shard_tuples = [(1, 43169837124188720964780342900310458552),
                    (3, 160134327314659478454450597353340529382),
                    (5, 91076994147313786513455993446030981984)]
    secret_int = recover_secret(shard_tuples)
    secret = int_to_secret(secret_int)
    return secret

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=prog_description)
    parser.add_argument('--split', help='TEXT', action='store_true')
    parser.add_argument('--join', help='TEXT', action='store_true')
    parser.add_argument('-s', '--secret', help='TEXT')
    parser.add_argument('-n', '--num-shards', help='TEXT', type=int, default=TOTAL_SHARDS)
    parser.add_argument('-m', '--min-shards', help='TEXT', type=int, default=MIN_SHARDS)
    parser.add_argument('-S', '--shard-files', help="TEXT", nargs='+')
    # parser.add_argument('-r', '--reconstruct', help="TEXT", nargs='+')
    # parser.add_argument('-c', '--shard-counter', help="TEXT", nargs='+')
    parser.add_argument('-V', '--version', help='Print the version information', action='store_true')
    
    # Parse command line
    args = parser.parse_args()

    if args.version:
        print(prog_description)
        print("Version: " + str(prog_version) + " (" + str(prog_date) + ")")
        exit()

    # Split the secret into shards
    if args.split:
        num_shards = args.num_shards
        min_shards = args.min_shards
        if not args.secret:
            secret = input("Please provide the secret to split:\n")
        else:
            secret = args.secret
        shards = split_secret(secret, min_shards, num_shards)
        for shard in shards:
            print(shard)
        return

    # Join the shards back into a secret
    if args.join:
        if type(args.shard_files) != list or len(args.shard_files) == 0:
            pass

        shard_files = args.shard_files

        for file in shard_files:
            # Check if it is a file
            # Parse JSON
            pass
        
        result = join_secrets(shard_files)
        print(result)
        return

if __name__ == '__main__':
    main()