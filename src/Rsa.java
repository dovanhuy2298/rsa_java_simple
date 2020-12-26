import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

public class Rsa
{

  private BigInteger N, phiN, p, q, e, d;

  private static Scanner in = new Scanner(System.in);

  public Rsa(int keySize)
  {
    if (keySize < 512)
      throw new IllegalArgumentException("Key size too small.");
    SecureRandom rand = new SecureRandom();
    generatePQ(keySize / 2, rand);
    // n = p*q
    N = p.multiply(q);
    // phiN = (p-1)*(q-1)
    phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    generateExponents(invertibleSet());
  }

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

  private BigInteger generateOddPrime(int bitLength, Random rand)
  {
    BigInteger two = new BigInteger("2");
    while (true)
    {
      /*
      Kiem tra so nguyen to:
      Y tuong: prime % (2 -> can2(prime)) != 0;
       */
      BigInteger prime = BigInteger.probablePrime(bitLength, rand);
      if (!prime.mod(two).equals(BigInteger.ZERO))
        return prime;
    }
  }

  private void generateExponents(BigInteger[] invertibleSet)
  {
    Random rand = new Random();
    while (true)
    {
      // Lay ra ngau nhien 1 so tu tap so E
      BigInteger invertible = invertibleSet[rand
          .nextInt(invertibleSet.length)];
      // d' = e' mod phiN
      BigInteger inverse = invertible.modInverse(phiN);
      // Neu d' * e' mod phiN == 1 => chon lam d, e;
      if (invertible.multiply(inverse).mod(phiN)
          .equals(BigInteger.ONE.mod(phiN)))
      {
        e = invertible;
        d = inverse;
        return;
      }
    }
  }

  private BigInteger[] invertibleSet()
  {
    final int maxSize = 100000;
    Set<BigInteger> invertibles = new HashSet<BigInteger>();
    //Chon e' = 5 -> n - 1
    BigInteger end = N.subtract(BigInteger.ONE);
    for (BigInteger i = new BigInteger("5"); i.compareTo(end) < 0; i = i
        .add(BigInteger.ONE))
    {
      // Kiem tra UCLN e' va phiN = 1 thi luu vao mang;
      /* Y thuong tinh gcd:
        while (a != b) {
            if (a > b) {
                a -= b;
            } else {
                b -= a;
            }
        };
        return a;
       */
      if (i.gcd(phiN).equals(BigInteger.ONE))
      {
        invertibles.add(i);
        if (invertibles.size() == maxSize)
          break;
      }
    }
    return invertibles.toArray(new BigInteger[invertibles.size()]);
  }

  public String encryptStr(String plainText)
  {
    BigInteger msg = new BigInteger(plainText.getBytes());
    // cirpher = plantext^e mod n
    /*
    Y tuong tinh m^e mod n:
    m %= n;
    result = 1;
    while (e > 0) {
      if (e == 1) result = (result * m) % n;
      m = (m * m) % n;
      e--;
    }
    return result;
     */
    byte[] encrypted = msg.modPow(e, N).toByteArray();
    return toHex(encrypted);
  }

  public String decryptStr(String cipherText)
  {
    BigInteger encrypted = new BigInteger(cipherText, 16);
    // cirpher = plantext^e mod n
    return new String(encrypted.modPow(d, N).toByteArray());
  }

  private String toHex(byte[] bytes)
  {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
  }

  public BigInteger getPhiN() {
    return phiN;
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getQ() {
    return q;
  }

  public BigInteger getModulus()
  {
    return N;
  }

  public BigInteger getPublicKeyExponent()
  {
    return e;
  }

  public BigInteger getPrivateKeyExponent()
  {
    return d;
  }

  public static void main(String[] args)
  {
    System.out.println("Moi chon kich co khoa ( >= 512 byte): ");
    int keySize = Integer.parseInt(in.nextLine());
    Rsa cipher = new Rsa(keySize);
    System.out.println("\nP :" + cipher.getP() + "\nQ: " + cipher.getQ());
    System.out.println("Cap khoa Key(e,n): " + cipher.getPublicKeyExponent() + ", " + cipher.getModulus());
    System.out.println("Cap khoa Key(d,n): " + cipher.getPrivateKeyExponent() + ", " + cipher.getModulus());
    while (true) {
      System.out.println("==============================");
      System.out.println("Nhap vao 1 de ma hoa 1 so.");
      System.out.println("Nhap vao 2 de ma hoa 1 chuoi.");
      System.out.println("Nhap vao 3 de giai ma 1 so.");
      System.out.println("Nhap vao 4 de giai ma 1 chuoi.");
      System.out.println("Nhap vao 5 de thoat.");
      System.out.println("==============================");
      int choice;
      choice = Integer.parseInt(in.nextLine());
      switch (choice) {
        case 1:
          System.out.println("Moi nhap vao so can ma hoa: ");
          String num = in.nextLine();
          BigInteger encodeNum = new BigInteger(num);
          System.out.println("So duoc ma hoa: " + encodeNum.modPow(cipher.getPublicKeyExponent(), cipher.getModulus()));
          break;
        case 2:
          System.out.println("Moi nhap vao chuoi can ma hoa: ");
          String msg = in.nextLine();
          String cipherText = cipher.encryptStr(msg);
          System.out.println("Chuoi sau khi duoc ma hoa dang (HEX): " + cipherText);
          break;
        case 3:
          System.out.println("Moi nhap vao so de giai ma: ");
          String num2 = in.nextLine();
          BigInteger decodeNum = new BigInteger(num2);
          System.out.println("So duoc ma hoa: " + decodeNum.modPow(cipher.getPrivateKeyExponent(), cipher.getModulus()));
          break;
        case 4:
          System.out.println("Moi nhap vao chuoi can giai ma: ");
          String cirpherText = in.nextLine();
          String planText = cipher.decryptStr(cirpherText);
          System.out.println("Ban ro: " + planText);
          break;
        case 5:
          System.exit(0);
        default:
          System.out.println("Moi chon lai chuc nang.");
          break;
      }
    }
  }

}