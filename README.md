# Simple Shamir's Secret Sharing (S4)

- [Simple Shamir's Secret Sharing (S4)](#simple-shamirs-secret-sharing-s4)
  - [Introduction](#introduction)
  - [Usage](#usage)
    - [Split a Secret](#split-a-secret)
    - [Reconstruct a Secret](#reconstruct-a-secret)
  - [Limitations](#limitations)


This is an expirmental implementation of [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) algorithm based on the code samples in the linked Wikipedia article.

**Do not use this implementation for production use cases, it is likely insecure!** This is just a fun project to understand how the algorithm works, and not a security tool.

## Introduction

If you want to learn more about Shamir's Secret Sharing algorithm, I recommend to start with the Wikipedia article linked above.  
In short, the algorithm can be used to split a secret (e.g. a passphrase or other secret key) into multiple (`n`) _shards_ or _shares_. These can then be distributed to multiple people or entities, and the algorithm guaratees (if implemented correctly) that no single shard can be used to retrieve any information about the original secret.  
A minimum number of shards required (`m`) can be defined, and any combination of shards (at least `m` out of `n`) can be used to reconstruct the original secret.

That way you can split a key between 5 friends (`n = 5`) and require a minmum of 3 (`m = 3`) of them to rebuild the key.

## Usage

To get the full help, execute:

```bash
python3 ./sss.py --help
```

### Split a Secret

To split a secret/create shards, use the `--split` flag. If you do not provide the secret to split (with `-s` or `--secret`) you will be prompted on the cli.  
Optionally, you can define the number of shards with `-n`/`--num-shards` (defaults to 5) and the minimum number required for reconstruction with `-m`/`--min-shards` (defaults to 3).

The shards will be exported into JSON files in the `./shards` folder. The JSON provides additional metadata, such as the fingerprints of the other shards for integrity checks and the total/minimum shards required. A sample file is provided [in the repo](./sample.shard.json).

**Examples:**

Prompt for the secret, split into 5 shards with a minimum of 3 for reconstruction:
```bash
python3 ./sss.py --split
```

Split the key "SuperSecret" into 3 shards with 2 required for reconstruction:
```bash
python3 ./sss.py --split -s SuperSecret -n 3 -m 2
```


### Reconstruct a Secret

To reconstruct, simply use the `--join` flag followed by the file paths to the individual shard files, for example:

```bash
python3 ./sss.py --join ./shards/1_090d375ec63e4bf29c4.json ./shards/2_4bf29c45442967008aw.json ./shards/4_e2cedac4e96778e98lh.json
```

Based on the metadata in the JSON files, the program checks if enough files are present for reconstruction, checks their fingerprints, and recombines the secret and prints it to `stdout`.

## Limitations

As stated above, **this is not a security tool**. The critical code is based on an example from Wikipedia, and has not been audited, so please **do not use this for anything where security is important**.

Furthermore, the length of the secret is heavily limited by the underlying implementation, I'll try to fix that in the future. Depending on the complexity (i.e. use of special characters) of the secret, the **limit is at around 12** characters.  
I recommend testing the reconstruction after splitting to see if it worked.