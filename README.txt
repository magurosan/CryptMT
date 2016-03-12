CryptMT version 3
C++ source code of a stream cipher CryptMT version 3.

The dynamic link library of CryptMT version 3 for Windows is included
in this windows version archive.

see LICENSE.txt

This archive also include a source file of cryptfile, which is
an application program.
usage:
./cryptfile [-e|-d] [-i ifile] [-o ofile] [-k key] [-f kfile] [-s size] [-v]

-e           Encryption.
-d           Decryption.
             If omitted encryption is assumed. But encryption
             and decryption are just the same.
-i ifile     Input file. If omitted, standard input is used.
-o ofile     Output file. If omitted, standard output is used.
-k key       Key for encryption/decryption.
-f kfile     File which contains encryption/decryption key.
             If both of -k and -f are omitted, user
             will be prompted to input the key.
             If both of -k and -f are specified, -k will be used.
-s size      Size of key. Size should be multiple of 128 and less
             than or equals to 2048. If omitted 128 is used.
-v           Show detailed message
