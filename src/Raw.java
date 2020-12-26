import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

/**
 * An efficient implementation of the RSA public-key cipher. All generated
 * exponents used for encryption and decryption are greater than <code>5</code>
 * (to secure against basic attacks, e.g. Chinese Remainder Theorem). The
 * cryptographically strong {@link SecureRandom} RNG is used to generate primes.
 * Note that this implementation is NOT to be used in production systems. By no
 * means does it follow NIST standards for cryptographic primitives. See the JCE
 * (Java Cryptography Extension).
 *
 * @author Ryan Beckett
 */
public class Raw
{

  private BigInteger N, phiN, p, q, e, d;

  /**
   * Construct a new instance of the RSA cipher.
   *
   * @param keySize
   *            The desired bit length of the RSA key. It is recommended that
   *            the key size be 1024-bits and that it be a power of 2 (or you
   *            might see unexpected behavior). At key sizes grow, the cipher
   *            takes longer.
   * @throws IllegalArgumentException
   *             If <code>keySize</code> is less than 512 bits.
   */
  public Raw(int keySize)
  {
    if (keySize < 512)
      throw new IllegalArgumentException("Key size too small.");
    SecureRandom rand = new SecureRandom();
    generatePQ(keySize / 2, rand);
    N = p.multiply(q);
    phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    generateExponents(invertibleSet());
  }

  /**
   * Generate <code>p</code> and <code>q</code>, where <code>p</code> and
   * <code>q</code> are random, distinct, and odd primes of size
   * <code>bitLength</code> using the RNG <code>rand</code>.
   *
   * @param bitLength
   *            The required bit size of the two primes.
   * @param rand
   *            The random number generator.
   */
  private void generatePQ(int bitLength, Random rand)
  {
    while (true)
    {
      p = generateOddPrime(bitLength, rand);
      q = generateOddPrime(bitLength, rand);
      if (!p.equals(q))
        return;
    }
  }

  /**
   * Generate an odd prime of length <code>bitLength</code> using the given
   * random number generator.
   *
   * @param bitLength
   *            The required bit size of the prime.
   * @param rand
   *            The random number generator.
   * @return An odd prime as a {@link BigInteger}.
   */
  private BigInteger generateOddPrime(int bitLength, Random rand)
  {
    BigInteger two = new BigInteger("2");
    while (true)
    {
      BigInteger prime = BigInteger.probablePrime(bitLength, rand);
      if (!prime.mod(two).equals(BigInteger.ZERO))
        return prime;
    }
  }

  /**
   * Generate the the public- and private-key exponents, <code>e</code> and
   * <code>d</code> respectively, from the set of invertible elements in
   * <code>Z_phiN</code>, such that <code>e * d = 1 (mod phiN)</code>. We just
   * choose a random <code>e</code> from a set of <code>10^5</code>
   * possibilities.
   *
   * @param invertibleSet
   *            The set of all invertible elements in <code>Z_phiN</code>.
   */
  private void generateExponents(BigInteger[] invertibleSet)
  {
    Random rand = new Random();
    while (true)
    {
      BigInteger invertible = invertibleSet[rand
          .nextInt(invertibleSet.length)];
      BigInteger inverse = invertible.modInverse(phiN);
      if (invertible.multiply(inverse).mod(phiN)
          .equals(BigInteger.ONE.mod(phiN)))
      {
        e = invertible;
        d = inverse;
        return;
      }
    }
  }

  /**
   * Generate the set of first <code>10^5</code> invertible elements in
   * <code>Z_phiN</code> , where an element <code>x</code> is in the set if
   * <code>gcd(x, phiN) = 1</code>. Throw out all elements less than 5, so
   * that the public-key exponent <code>e</code> is guaranteed to be greater
   * than 5.
   *
   * @return An array of invertible elements in <code>Z_phiN</code>.
   */
  private BigInteger[] invertibleSet()
  {
    final int maxSize = 100000;
    Set<BigInteger> invertibles = new HashSet<BigInteger>();
    BigInteger end = N.subtract(BigInteger.ONE);
    for (BigInteger i = new BigInteger("5"); i.compareTo(end) < 0; i = i
        .add(BigInteger.ONE))
    {
      if (i.gcd(phiN).equals(BigInteger.ONE))
      {
        invertibles.add(i);
        if (invertibles.size() == maxSize)
          break;
      }
    }
    return invertibles.toArray(new BigInteger[invertibles.size()]);
  }

  /**
   * Encrypt the given plain text. The plain text is converted to decimal form
   * before encrypting with the public key.
   *
   * @param plainText
   *            The plain text.
   * @return The encrypted plain text as a hex string.
   */
  public String encrypt(String plainText)
  {
    BigInteger msg = new BigInteger(plainText.getBytes());
    byte[] encrypted = msg.modPow(e, N).toByteArray();
    return toHex(encrypted);
  }

  /**
   * Decrypt the given cipher text. The cipher text is converted to decimal
   * form before decrypting with the private key.
   *
   * @param cipherText
   *            The cipher text.
   * @return The original plain text string.
   */
  public String decrypt(String cipherText)
  {
    BigInteger encrypted = new BigInteger(cipherText, 16);
    return new String(encrypted.modPow(d, N).toByteArray());
  }

  /**
   * Convert an array of bytes to a hex string.
   *
   * @param bytes
   *            The bytes to convert.
   * @return The hex string.
   */
  private String toHex(byte[] bytes)
  {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
  }

  /**
   * Get the RSA modulus.
   *
   * @return The modulus as a {@link BigInteger}.
   */
  public BigInteger getModulus()
  {
    return N;
  }

  /**
   * Get the public key exponent.
   *
   * @return The exponent as a {@link BigInteger}.
   */
  public BigInteger getPublicKeyExponent()
  {
    return e;
  }

  /**
   * Get the private key exponent.
   *
   * @return The exponent as a {@link BigInteger}.
   */
  public BigInteger getPrivateKeyExponent()
  {
    return d;
  }

  /**
   * A sample usage of the cipher.
   */
  public static void main(String[] args)
  {
    int keySize = 1024;
    Raw cipher = new Raw(keySize);
    String msg = "Attack at dawn! Go to the barracks and wait out the order.";
    String cipherText = cipher.encrypt(msg);
    System.out.println("Original Message: " + msg);
    System.out.println("cipher text: " + cipherText);
    System.out.println("plain text: " + cipher.decrypt(cipherText));
  }

}