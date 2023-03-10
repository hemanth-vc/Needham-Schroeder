import TDESSecurity.TDESSecurity;

import java.net.*;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

public class KDCReflection {
    static final String idAlice = new String("8018142327");
    static final String idBob = new String("8019351793");

    static final byte[] aliceKey = "7mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceKey, "TripleDES");
    static final byte[] aliceKeyiv = "B76mb5h9".getBytes();
    static final IvParameterSpec aliceKeyivSpec = new IvParameterSpec(aliceKeyiv);

    static final byte[] bobKey = "9mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec bobKeySpec = new SecretKeySpec(bobKey, "TripleDES");
    static final byte[] bobKeyiv = "a76mb5h9".getBytes();
    static final IvParameterSpec bobKeyivSpec = new IvParameterSpec(bobKeyiv);

    public static void main(String args[])
    {
        //Common methods are written in TDESSecurity
        TDESSecurity tDESSecurity = new TDESSecurity();

        //Creating a socket to connect with Alice and KDC
        try {
            System.out.println("KDCReflection has started.");
            ServerSocket serverSocket = new ServerSocket(1234);
            Socket server = serverSocket.accept();
            server.setSoTimeout(100000);
            System.out.println("KDC established connection with Alice.");

            //Creating a bufferreader and printwriter to print to and read from socket stream.
            BufferedReader br = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter pw = new PrintWriter(server.getOutputStream(), true);

            //received Alice's information and verify his identity with the id
            String n1 = br.readLine();
            String idAliceRcd = br.readLine();
            String idBobRcd = br.readLine();

            //if verification was successful, send him the ticket and random key
            if (idAliceRcd.equals(idAlice) && idBobRcd.equals(idBob)) {
            String ABKey = tDESSecurity.giveRandomKey();
            System.out.println("ABKey generated: " + ABKey);
            String ticketToBob = tDESSecurity.EncryptTDES(ABKey+";"+idAlice,bobKeySpec, bobKeyivSpec); 
            System.out.println("ticketToBob is: "+ticketToBob);
            String ticketDetails = tDESSecurity.EncryptTDES(n1+";"+idBobRcd+";"+ABKey+";"+ticketToBob, aliceKeySpec, aliceKeyivSpec);
            System.out.println("ticketDetails is: "+ticketDetails);
            pw.println(ticketDetails);
            }
            else
            {System.out.println("Liar! Liar! Pants on fire! YOU ARE NOT ALICE");}

            //close connections
            server.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
