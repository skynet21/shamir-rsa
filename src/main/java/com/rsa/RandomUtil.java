package com.rsa;

import java.security.SecureRandom;

/**
 * 
 * @author Chris Mack
 *
 */
public class RandomUtil {
  private static final String CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  private static final SecureRandom RANDOM = new SecureRandom();

  public static final String generateString(final int length) {
    final StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++)
      sb.append(CHARS.charAt(RANDOM.nextInt(CHARS.length())));
    return sb.toString();
  }

  public static final int generateInt(final int limit) {
    return RANDOM.nextInt(limit);
  }
}
