package com.rsa;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 * @author Chris Mack
 *
 */
public class Shamir {

  public static final Map<Integer, byte[]> generateShardedKey(final int n, final int k) {
    // Creates the RSA key pair
    final KeyPair keyPair = ShamirRSAUtil.generateNewKeyPair();

    // write public key file
    FileUtil.writeFileHexFormat("Public.TXT", keyPair.getPublic().getEncoded());
    // write private key shard files
    final Map<Integer, byte[]> privateKeyParts = ShamirRSAUtil.shamirSplit(n, k, keyPair.getPrivate().getEncoded());
    for (Entry<Integer, byte[]> entry : privateKeyParts.entrySet()) {
      FileUtil.writeFileHexFormat("Shard[" + entry.getKey().intValue() + "].TXT", entry.getValue());
    }
    return privateKeyParts;
  }

  public static final void encryptFile(final String inputFilename) throws IOException {
    // load data
    final Path path = Paths.get(inputFilename);
    final byte[] data = Files.readAllBytes(path);

    // load public key from file
    final byte[] publicKeyBytes = FileUtil.readFileHexFormat("Public.TXT");
    final PublicKey publicKey = ShamirRSAUtil.buildPublicKey(publicKeyBytes);

    // encrypt
    byte[] encryptedData = ShamirRSAUtil.encrypt(publicKey, data);
    FileUtil.writeFileHexFormat(inputFilename + ".encrypted", encryptedData);
  }

  public static final void decryptFile(final int n, final int k, final String inputFilename) throws IOException {
    // load encrypted data
    final byte[] encryptedData = FileUtil.readFileHexFormat(inputFilename);

    // Reassembles the Private Key using shard 2 & 5. from files
    final Map<Integer, byte[]> parts = new HashMap<>();
    for (int i = 1; i <= n; i++) {
      final byte[] shard = FileUtil.readFileHexFormat("Shard[" + i + "].TXT");
      parts.put(i, shard);
    }

    // use parts to recover private key
    byte[] privateKeyBytes = ShamirRSAUtil.shamirJoin(n, k, parts);
    final PrivateKey recoveredPrivateKey = ShamirRSAUtil.buildPrivateKey(privateKeyBytes);

    final byte[] decryptedData = ShamirRSAUtil.decrypt(recoveredPrivateKey, encryptedData);
    FileUtil.writeFile(inputFilename + ".decryped", decryptedData);
  }

  public static final void help() {
    System.out.println("Usage:");
    System.out.println("java Shamir shard-key <n> <k>");
    System.out.println("java Shamir encrypt <filename to encrypt>");
    System.out.println("java Shamir decrypt <n> <k> <filename to decrypt>");
    System.exit(0);
  }

  public static void main(final String[] args) {
    try {
      if (args.length < 2)
        help();

      switch (args[0]) {
        case "shard-key":
          generateShardedKey(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
          break;
        case "encrypt":
          encryptFile(args[1]);
          break;
        case "decrypt":
          decryptFile(Integer.parseInt(args[1]), Integer.parseInt(args[2]), args[3]);
          break;
        default:
          help();
      }
      System.out.println("done");
    } catch (Exception e) {
      e.printStackTrace();
      help();
    }
  }
}
