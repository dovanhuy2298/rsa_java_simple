import java.util.Scanner;

public class Rsa {

  Scanner in = new Scanner(System.in);

  boolean checkIsPrime(long num) {
    if( num < 2 ) {
      return true;
    }
    long i = 2;
    while (i <= num/2) {
      if( num%i == 0 ) {
        return true;
      }
      i++;
    }
    return false;
  }

  long Multiply(long num1, long num2) {
    return num1*num2;
  }

  boolean checkCoPrime(long num1, long num2) {
    long r, a, b;
    if(num1 > num2) {
      a=num1; b=num2;
    } else {
      a=num2; b=num1;
    }
    while (b != 0) {
      r=a%b;
      a=b; b=r;
    }
    return a != 1;
  }

  long findE(long phi_n) {
    long e = 0;
    while (e >= phi_n || e <= 1) {
      System.out.println("Chon so e:  1 < e < phi_n = " + phi_n);
      System.out.println("Nhap vao e nguyen to cung nhau voi phi_n: ");
      e = Long.parseLong(in.nextLine());
    }
    if (checkCoPrime(phi_n, e)) {
      System.out.println("Phi_n khong nguyen to cung nhau voi e.");
      while (checkCoPrime(phi_n, e)) {
        e++;
      }
      System.out.println("He thong tu chon e = " + e);
    }
    return e;
  }

  long findD(long phi_n, long e) {
    long a = phi_n, b = e;
    long x1 = 0, x2 = 1, y1 = 1, y2 = 0, x, y, q, r;
    while (b != 0) {
      q = a/b;
      r = a%b;
      x = x2 - (x1 * q);
      y = y2 - (y1 * q);
      a = b;
      b = r;
      x2 = x1; x1 = x;
      y2 = y1; y1 = y;
    }
    if (a != 1) {
      System.out.println("Chon 1 so e phu hop: ");
      e = findE(phi_n);
      findD(phi_n, e);
    }
    x = x2; y = y2;
    if( y < 0) {
      y = phi_n + y;
    }
    return y;
  }

  long encryptOrDecrypt(long t, long e, long n) {
    long rem;
    long x = 1;
    while(e!=0)
    {
      rem = e % 2;
      e = e/2;
      if (rem==1) {
        x = (x*t)% n;
      }
      t = (t*t)%n;
    }
    return x;
  }

  void encDecNum(long n1, long n2) {
    long pn;
    System.out.println("Nhap vao 1 so nguyen: ");
    pn = Long.parseLong(in.nextLine());
    System.out.println(encryptOrDecrypt(pn, n1, n2));
  }

  void encDecStr(long e, long n) {
    String str;
    StringBuilder str1 = new StringBuilder();
    System.out.println("Nhap vao mot chuoi bat ky: ");
    str = in.nextLine();
    for (int i = 0; i < str.length(); i++) {
      long temp = encryptOrDecrypt(str.charAt(i), e, n);
      str1.append((char) temp);
    }
    System.out.println("Ban ma dang string: " + str1);
    System.out.print("Ban ma dang ASCII: ");
    for(int i=0; i<str1.length(); i++)
    {
      int asciiValue = str1.charAt(i);
      System.out.print(asciiValue);
    }
    System.out.println("");
  }

  KeyRsa generateKey() {
    KeyRsa keyRsa = new KeyRsa();
    while (checkIsPrime(keyRsa.getP())) {
      System.out.println("Moi nhap 1 so nguyen to (p):");
      long p = Long.parseLong(in.nextLine());
      keyRsa.setP(p);
    }
    while (checkIsPrime(keyRsa.getQ())) {
      System.out.println("Moi nhap 1 so nguyen to (q):");
      long q = Long.parseLong(in.nextLine());
      keyRsa.setQ(q);
    }
    keyRsa.setN(Multiply(keyRsa.getP(), keyRsa.getQ()));
    System.out.println("Gia tri n: " + keyRsa.getN());
    keyRsa.setPhi_n(Multiply(keyRsa.getP() - 1, keyRsa.getQ() -1));
    System.out.println("Gia tri phi_n: " + keyRsa.getPhi_n());
    keyRsa.setE(findE(keyRsa.getPhi_n()));
    keyRsa.setD(findD(keyRsa.getPhi_n(), keyRsa.getE()));
    System.out.println("Gia tri Publickey(e,n): " + keyRsa.getE() + "," + keyRsa.getN());
    System.out.println("Gia tri PrivateKey(d,n): " + keyRsa.getD() + "," + keyRsa.getN());
    return keyRsa;
  }

}
