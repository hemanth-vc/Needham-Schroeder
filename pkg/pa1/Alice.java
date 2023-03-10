import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.StringTokenizer;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import TDESSecurity.TDESSecurity;

public class Alice {
    //Initializing final string idALice and ibBob to identify Alice and Bob. This is known to everyone.
    static final String idALice = new String("8018142327");
    static final String idBob = new String("8019351793");

    //Initializing Alice's private key and declaring the encrypting algorithm as TripleDES. Also declaring the Initializing Vector(iv)
    static final byte[] aliceKey = "7mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceKey, "TripleDES");
    static final byte[] aliceKeyiv = "B76mb5h9".getBytes();
    static final IvParameterSpec aliceKeyivSpec = new IvParameterSpec(aliceKeyiv);


    public static void main(String args[]) throws IOException {
        //Common methods are written in TDESSecurity
        TDESSecurity tDESSecurity = new TDESSecurity();

        try {
            System.out.println("Alice has started.");

            //Creating a socket to connect with Bob and KDC
            Socket socket = new Socket("localhost", 1235);
            socket.setSoTimeout(100000);
            System.out.println("Alice established connection with Bob");
            Socket socketKDC = new Socket("localhost", 1234);
            System.out.println("Alice established connection with KDC");
            
            //Creating a bufferreader and printwriter to print to and read from socket stream.
            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            //Creating a bufferreader and printwriter to print to and read from the KDC socket stream.
            PrintWriter pwKDC = new PrintWriter(socketKDC.getOutputStream(), true);
            BufferedReader brKDC = new BufferedReader(new InputStreamReader(socketKDC.getInputStream()));            
            
            //Alice initiates communicaiton with KDC for session key generation.
            pw.println("hey");
            pw.println(idALice);
            String nbEncoded = br.readLine();
            System.out.println("Encrypted nb is: " + nbEncoded);
            long n1 = tDESSecurity.giveRandom();
            pwKDC.println(String.valueOf(n1));
            pwKDC.println(idALice);
            pwKDC.println(idBob);
            pwKDC.println(nbEncoded);

            //receive random key and ticket details from KDC
            String ticketDetails = brKDC.readLine();
            String decryptedTicketDetails = tDESSecurity.DecryptTDES(ticketDetails,aliceKeySpec, aliceKeyivSpec);
            StringTokenizer tokenizer = new StringTokenizer(decryptedTicketDetails,";");
            String n1Rcd = tokenizer.nextToken();
            String idBobRcd = tokenizer.nextToken();
            String ABKey = tokenizer.nextToken();
            String ticketToBob = tokenizer.nextToken();

            //print details to the output console
            System.out.println("n1: "+n1+" n1 received: "+n1Rcd);
            System.out.println("idBob: "+idBob+" idBob received:"+idBobRcd);
            System.out.println("ABKey: " + ABKey);
            System.out.println("ticketToBob: "+ ticketToBob);

            //set up the session key and start communicating with Bob
            final byte[] ABKeyBytes = ABKey.getBytes();
            final SecretKeySpec ABKeySpec = new SecretKeySpec(ABKeyBytes, "TripleDES");
            final byte[] ABKeyiv = "C76mb5h9".getBytes();
            final IvParameterSpec ABKeyivSpec = new IvParameterSpec(ABKeyiv);
            long n2 = tDESSecurity.giveRandom();
            System.out.println("n2 is: "+String.valueOf(n2));
            pw.println(ticketToBob);
            String message5p2 = tDESSecurity.EncryptTDES(String.valueOf(n2), ABKeySpec, ABKeyivSpec);
            pw.println(message5p2);

            //received challenge from Bob to authenticate Alice
            String message6 = br.readLine();
            String message6decrypted = tDESSecurity.DecryptTDES(message6, ABKeySpec, ABKeyivSpec);
            System.out.println("message6decrypted: "+ message6decrypted);
            StringTokenizer tokenizer2 = new StringTokenizer(message6decrypted, ";");
            String n2updated = tokenizer2.nextToken();
            String n3 = tokenizer2.nextToken();
                        
            //challenge solution is computed and also checks response to the challege sent and verifies the solution.
            System.out.println("n2-1 is: " + n2updated);
            System.out.println("n3 is: "+ n3);
            long n3updated = Long.parseLong(n3) -1;
            String message7 = tDESSecurity.EncryptTDES(String.valueOf(n3updated), ABKeySpec, ABKeyivSpec);
            if(Long.parseLong(n2updated)==(n2-1))
            {
                System.out.println("n2 and n2-1 is verified at Alice. Authentication Successful!");
                pw.println(message7);
            }

            //close connection
            socket.close();
            socketKDC.close();

        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}