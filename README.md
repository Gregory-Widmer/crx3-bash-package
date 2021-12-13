# CRX3 Bash packager

This script packages an unpacked chroomium extension into a CRX file (version 3).

## Dependencies

This script requires having those programs in your `PATH` variable :

- `zip` : Used to compress a folder.
- `openssl` : Used to sign data and manage private key.
- `xxd` : Used to transform bytes to hex and hex to bytes. Usually packaged with `vim`.
- `awk` : Used to parse `ls` output.
- Standard linux commands : `ls`, `rm`, `cd`, `cat`
- Bash

## How to use ?

You can clone this repository or copy directly the contents of `package.sh` into a script.

Make the script runnable with `chmod u+x package.sh`.

**This script was designed to be used with Gitlab CI/CD, the private key used to sign data is then passed as an argument, not a file.**
*(Please note that due to openssl command syntax, the script temporarily stores the private key in a file named `key.tmp`)*

Run the script with the following syntax : `./package.sh <Input folder> <Private key> [Output file name]`

- `Input folder` **MANDATORY** : The folder to package
- `Private key` **MANDATORY** : The private key content, **NOT** the filename
- `Output file name` **OPTIONAL** : The output file name, by default `extension.crx`

## Contributing

Feel free to open PR and issues if you need.

I will try to answer quickly.


