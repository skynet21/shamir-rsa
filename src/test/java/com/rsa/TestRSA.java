package com.rsa;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 * @author Chris Mack
 *
 */
public class TestRSA {
  /* @formatter:off
   * n the number of parts to produce (must be >1) k the threshold of joinable parts (must be <= n)
   * 
   * Demonstrate that the program works correctly, by creating a unit test that:

    The program should write the public key to a text file called Public.TXT, and the private key shards to text files called Shard[k].TXT.

    1.Creates the RSA key pair with a Private Key broken into 5 shards.
    2.Encrypts a random plain text string using the RSA Public Key.
    3.Reassembles the Private Key using shard 2 & 5.
    4.Decrypts the cypher text back into the plain text using the reassembled Private Key.
    5.Asserts the decrypted plain text is equal to the original random plain text in Step 2.
    
    @formatter:on
   */

  @Test
  public final void encryptDecryptTest1() {
    int n = 5;
    int k = 2;
    final String secret = RandomUtil.generateString(16);

    // Creates the RSA key pair, shards, and saves files
    final Map<Integer, byte[]> privateKeyParts = Shamir.generateShardedKey(n, k);

    // load public key from file
    final byte[] publicKeyBytes = FileUtil.readFileHexFormat("Public.TXT");
    final PublicKey publicKey = ShamirRSAUtil.buildPublicKey(publicKeyBytes);

    // Reassembles the Private Key using shard 2 & 5. from files
    final byte[] shard2 = FileUtil.readFileHexFormat("Shard[2].TXT");
    final byte[] shard5 = FileUtil.readFileHexFormat("Shard[5].TXT");
    final Map<Integer, byte[]> parts = new HashMap<>();
    parts.put(2, shard2);
    parts.put(5, shard5);

    // use parts to recover private key
    byte[] privateKeyBytes = ShamirRSAUtil.shamirJoin(n, k, parts);
    final PrivateKey recoveredPrivateKey = ShamirRSAUtil.buildPrivateKey(privateKeyBytes);

    // decrypt encrypted data using recovered private key
    byte[] encryptedData = ShamirRSAUtil.encrypt(publicKey, secret.getBytes());
    final byte[] decryptedData = ShamirRSAUtil.decrypt(recoveredPrivateKey, encryptedData);
    final String decryptedSecret = new String(decryptedData, StandardCharsets.UTF_8);
    System.out.println("recovered: " + decryptedSecret);

    Assert.assertEquals(secret, decryptedSecret);
  }

}
