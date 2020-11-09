package com.rsa;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.Cipher;
import com.codahale.shamir.Scheme;

/**
 * 
 * @author Chris Mack
 *
 */
public class ShamirRSAUtil {
  public static final String RSA = "RSA";

  // generateNewKeyPair using RSA
  public static final KeyPair generateNewKeyPair() {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
      generator.initialize(2048);
      final KeyPair keyPair = generator.generateKeyPair();
      return keyPair;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  // build RSA private key from bytes
  public static final PrivateKey buildPrivateKey(final byte[] keyBytes) {
    try {
      final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      final KeyFactory kf = KeyFactory.getInstance(RSA);
      return kf.generatePrivate(spec);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  // build RSA public key from bytes
  public static final PublicKey buildPublicKey(final byte[] keyBytes) {
    try {
      final X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      final KeyFactory kf = KeyFactory.getInstance(RSA);
      return kf.generatePublic(spec);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  // encrypt data using RSA publicKey
  public static final byte[] encrypt(final Key publicKey, final byte[] data) {
    try {
      final Cipher rsa = Cipher.getInstance(RSA);

      rsa.init(Cipher.ENCRYPT_MODE, publicKey);
      rsa.update(data);
      final byte[] result = rsa.doFinal();

      return result;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  // decrypt data using RSA privateKey
  public static final byte[] decrypt(final Key privateKey, final byte[] encryptedData) {
    try {
      final Cipher rsa = Cipher.getInstance(RSA);
      rsa.init(Cipher.DECRYPT_MODE, privateKey);
      rsa.update(encryptedData);
      final byte[] result = rsa.doFinal();

      return result;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  // splits the data into parts
  // n the number of parts to produce (must be >1) k the threshold of joinable parts (must be <= n)
  public static final Map<Integer, byte[]> shamirSplit(final int n, final int k, final byte[] data) {
    final Scheme scheme = new Scheme(new SecureRandom(), n, k);
    final Map<Integer, byte[]> parts = scheme.split(data);
    return parts;
  }

  // joins data using shamir parts
  // n the number of parts to produce (must be >1) k the threshold of joinable parts (must be <= n)
  public static final byte[] shamirJoin(final int n, final int k, final Map<Integer, byte[]> parts) {
    final Scheme scheme = new Scheme(new SecureRandom(), n, k);
    final byte[] recovered = scheme.join(parts);
    return recovered;
  }

}
