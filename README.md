ShamirTest is a command line tool that encrypts and decrypts using a private key that is sharded with Shamir's algorithm.
n the number of parts to produce (must be >1) k the threshold of joinable parts (must be <= n)
shards are stored in files Shard[<k>].TXT

Usage:
java Shamir shard-key <n> <k>

java Shamir encrypt <filename to encrypt>

java Shamir decrypt <n> <k> <filename to decrypt>

Example:

java Shamir shard-key 5 5

java Shamir encrypt testdata.TXT

java Shamir decrypt 5 2 testdata.TXT.encrypted


It also contains a unit test TestRSA.encryptDecryptTest1() that uses a randomly generated input string.

The program should write the public key to a text file called Public.TXT, and the private key shards to text files called Shard[<k>].TXT.

1.Creates the RSA key pair with a Private Key broken into 5 shards.

2.Encrypts a random plain text string using the RSA Public Key.

3.Reassembles the Private Key using shard 2 & 5.

4.Decrypts the cypher text back into the plain text using the reassembled Private Key.

5.Asserts the decrypted plain text is equal to the original random plain text in Step 2.


