import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.StringTokenizer;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import TDESSecurity.TDESSecurity;

class Bob {
    // Initializing final string idALice to identify Alice. This is known to
    // everyone.
    static final String idAlice = new String("8018142327");

    //Initializing Bob's private key and declaring the encrypting algorithm as TripleDES. Also declaring the Initializing Vector(iv)
    static final byte[] bobKey = "9mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec bobKeySpec = new SecretKeySpec(bobKey, "TripleDES");
    static final byte[] bobKeyiv = "a76mb5h9".getBytes();
    static final IvParameterSpec bobKeyivSpec = new IvParameterSpec(bobKeyiv);

    public static void main(String args[]) {
        //Common methods are written in TDESSecurity
        TDESSecurity tDESSecurity = new TDESSecurity();
        long nb = tDESSecurity.giveRandom();

        try {
            System.out.println("Bob has started.");
            //Creating a socket to connect with ALice
            ServerSocket serverSocket = new ServerSocket(1235);
            Socket server = serverSocket.accept();
            server.setSoTimeout(100000);
            System.out.println("Bob established connection with Alice!");

            //Creating a bufferreader and printwriter to print to and read from socket stream.            
            BufferedReader br = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter pw = new PrintWriter(server.getOutputStream(), true);
            
            //wait for Alice to start communication and then verify Alice with his id.
            String str = br.readLine();
            System.out.println("Alice said: " + str);
            if (str.equals("hey")) {
                str = br.readLine();

                //If Alice is verified by his ID, send him Nb.
                if (str.equals(idAlice)) {
                    System.out.println(String.valueOf(nb));
                    String nbEncoded = tDESSecurity.EncryptTDES(String.valueOf(nb), bobKeySpec, bobKeyivSpec);
                    System.out.println("Encrypted nb is: " + nbEncoded);
                    pw.println(nbEncoded);
                }
            }

            //receive random key and ticket details from Alice
            String ticketToBob = br.readLine();
            String n2Encoded = br.readLine();
            System.out.println("Ticket received: " + ticketToBob);
            System.out.println("Encrypted n2: " + n2Encoded);

            //decrypt ticket to extract key and start communicating with Alice
            String ticketToBobDecrypted = tDESSecurity.DecryptTDES(ticketToBob, bobKeySpec, bobKeyivSpec);
            StringTokenizer tokenizer = new StringTokenizer(ticketToBobDecrypted, ";");
            String ABKey = tokenizer.nextToken();
            String idAliceRcd = tokenizer.nextToken();
            String nbRcd = tokenizer.nextToken();
            System.out.println("ABKey: " + ABKey);

            //after the key is ready send the solution to the challenge sent by Alice using the new session key.
            if (idAliceRcd.equals(idAlice) && nbRcd.equals(String.valueOf(nb))) {
                final byte[] ABKeyBytes = ABKey.getBytes();
                final SecretKeySpec ABKeySpec = new SecretKeySpec(ABKeyBytes, "TripleDES");
                final byte[] ABKeyiv = "C76mb5h9".getBytes();
                final IvParameterSpec ABKeyivSpec = new IvParameterSpec(ABKeyiv);
                String n2 = tDESSecurity.DecryptTDES(n2Encoded, ABKeySpec, ABKeyivSpec);
                System.out.println("n2 generated is: " + n2);
                long n2Updated = Long.parseLong(n2) - 1;
                
                //append Bob's challenge to Alice to authenticate using the session key.
                long n3 = tDESSecurity.giveRandom();
                System.out.println("n3 is: " + String.valueOf(n3));
                String message6 = tDESSecurity.EncryptTDES(String.valueOf(n2Updated) + ";" + String.valueOf(n3),
                        ABKeySpec, ABKeyivSpec);
                pw.println(message6);

                //verify solution sent by Alice to Bob's challenge
                String message7 = br.readLine();
                String message7decrypted = tDESSecurity.DecryptTDES(message7, ABKeySpec, ABKeyivSpec);
                System.out.println("n3-1 is: " + message7decrypted);
                                if (Long.parseLong(message7decrypted) == (n3 - 1)) {
                    System.out.println("n3 and n3-1 is verified at Bob. Authentication Successful!");

                }
            }

            //close connections
            server.close();
            serverSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}