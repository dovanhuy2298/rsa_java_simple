import java.util.Scanner;

public class Main {

  public static void main(String[] args) {
    Scanner in = new Scanner(System.in);

    System.out.println("###Chuong trinh thuat toan R.S.A su dung JAVA");
    Rsa rsa = new Rsa();
    KeyRsa keyRsa = rsa.generateKey();
    while (true) {
      System.out.println("==============================");
      System.out.println("Nhap vao 1 de ma hoa 1 so.");
      System.out.println("Nhap vao 2 de ma hoa 1 chuoi.");
      System.out.println("Nhap vao 3 de giai ma 1 so.");
      System.out.println("Nhap vao 4 de giai ma 1 chuoi.");
      System.out.println("Nhap vao 5 de thoat.");
      System.out.println("==============================");
      int choice;
      choice = in.nextInt();
      switch (choice) {
        case 1:
          rsa.encDecNum(keyRsa.getE(), keyRsa.getN());
          break;
        case 2:
          rsa.encDecStr(keyRsa.getE(), keyRsa.getN());
          break;
        case 3:
          rsa.encDecNum(keyRsa.getD(), keyRsa.getN());
          break;
        case 4:
          rsa.encDecStr(keyRsa.getD(), keyRsa.getN());
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
