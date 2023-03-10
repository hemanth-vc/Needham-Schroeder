import TDESSecurity.TDESSecurity;

import java.net.*;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

class KDC {

    //Initializing final string idALice and ibBob to identify Alice and Bob. This is known to everyone.
    static final String idAlice = new String("8018142327");
    static final String idBob = new String("8019351793");
    
    //Initializing Alice's private key and declaring the encrypting algorithm as TripleDES. Also declaring the Initializing Vector(iv)
    static final byte[] aliceKey = "7mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceKey, "TripleDES");
    static final byte[] aliceKeyiv = "B76mb5h9".getBytes();
    static final IvParameterSpec aliceKeyivSpec = new IvParameterSpec(aliceKeyiv);

    //Initializing Bob's private key and declaring the encrypting algorithm as TripleDES. Also declaring the Initializing Vector(iv)
    static final byte[] bobKey = "9mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec bobKeySpec = new SecretKeySpec(bobKey, "TripleDES");
    static final byte[] bobKeyiv = "a76mb5h9".getBytes();
    static final IvParameterSpec bobKeyivSpec = new IvParameterSpec(bobKeyiv);

    public static void main(String args[]) {
        TDESSecurity tDESSecurity = new TDESSecurity();
        try {
            System.out.println("KDC has started.");
            
            //Creating a socket to connect with Alice and KDC
            ServerSocket serverSocket = new ServerSocket(1234);
            Socket server = serverSocket.accept();
            server.setSoTimeout(100000);
            System.out.println("Connection established!");

            //Creating a bufferreader and printwriter to print to and read from socket stream.
            BufferedReader br = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter pw = new PrintWriter(server.getOutputStream(), true);

            //received Alice's information and verify his identity with the id
            String n1 = br.readLine();
            String idAliceRcd = br.readLine();
            String idBobRcd = br.readLine();
            String nbEncoded = br.readLine();
            if (idAliceRcd.equals(idAlice) && idBobRcd.equals(idBob)) {
                String nbDecoded = tDESSecurity.DecryptTDES(nbEncoded, bobKeySpec, bobKeyivSpec);
                System.out.println("nb decoded is: " + nbDecoded);
            
            //generate a random Kab along with the ticket and send it to Alice.
            String ABKey = tDESSecurity.giveRandomKey();
            System.out.println("ABKey generated: " + ABKey);
            String ticketToBob = tDESSecurity.EncryptTDES(ABKey+";"+idAlice+";"+nbDecoded,bobKeySpec, bobKeyivSpec); 
            System.out.println("ticketToBob is: "+ticketToBob);
            String ticketDetails = tDESSecurity.EncryptTDES(n1+";"+idBobRcd+";"+ABKey+";"+ticketToBob, aliceKeySpec, aliceKeyivSpec);
            System.out.println("ticketDetails is: "+ticketDetails);
            pw.println(ticketDetails);
            }
            else
            {System.out.println("Liar! Liar! Pants on fire! YOU ARE NOT ALICE");}

            //close connection
            server.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}