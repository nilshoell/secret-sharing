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

def split_secret():
    pass

def join_secrets():
    pass

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description=prog_description)
    parser.add_argument('-s', '--secret', help='TEXT')
    parser.add_argument('-n', '--num-shards', help='TEXT', type=int, default=TOTAL_SHARDS)
    parser.add_argument('-m', '--min-shards', help='TEXT', type=int, default=MIN_SHARDS)
    parser.add_argument('-r', '--reconstruct', help="TEXT", nargs='+')
    parser.add_argument('-c', '--shard-counter', help="TEXT", nargs='+')
    parser.add_argument('-V', '--version', help='Print the version information', action='store_true')
    
    # Parse command line
    args = parser.parse_args()

    if args.version:
        print(prog_description)
        print("Version: " + str(prog_version) + " (" + str(prog_date) + ")")
        exit()

    secret = args.secret
    num_shards = args.num_shards
    min_shards = args.min_shards
    reconstruct = args.reconstruct
    shard_counter = args.shard_counter

    if args.reconstruct and len(reconstruct) > 0:
        shards = []
        i = 0
        for shard in reconstruct:
            shards.append((int(shard_counter[i]), int(shard)))
            i += 1

        recovered_secret = recover_secret(shards)
        print(recovered_secret)
        return

    if args.secret and secret != "":
        secret = int(args.secret)
        shards = make_random_shares(secret, minimum=min_shards, shares=num_shards)
        for shard in shards:
            print(shard)

if __name__ == '__main__':
    main()