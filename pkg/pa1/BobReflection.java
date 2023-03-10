import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
import java.util.StringTokenizer;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import TDESSecurity.TDESSecurity;

public class BobReflection {
    //Initializing final string idALice to identify Alice. This is known to everyone.
    static final String idAlice = new String("8018142327");

    //Initializing Bob's key Kb and Iv
    static final byte[] bobKey = "9mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec bobKeySpec = new SecretKeySpec(bobKey, "TripleDES");
    static final byte[] bobKeyiv = "a76mb5h9".getBytes();
    static final IvParameterSpec bobKeyivSpec = new IvParameterSpec(bobKeyiv);
    public static void main(String args[])
    {
        TDESSecurity tDESSecurity = new TDESSecurity();

        try {
            System.out.println("BobReflection has started.");
            //Connect with Alice using a a socket.
            ServerSocket serverSocket = new ServerSocket(1235);
            Socket server = serverSocket.accept();
            server.setSoTimeout(100000);
            System.out.println("Connection established with Alice!");

            //Creating a bufferreader and printwriter to print to and read from the socket stream.
            BufferedReader br = new BufferedReader(new InputStreamReader(server.getInputStream()));
            PrintWriter pw = new PrintWriter(server.getOutputStream(), true);

            String ticketToBob = br.readLine();
            String n2encrypted = br.readLine();

            System.out.println("Ticket received: " + ticketToBob);
            System.out.println("Encrypted n2: " + n2encrypted);

            //Decrypt the ticket received and extract the Key
            String ticketToBobDecrypted = tDESSecurity.DecryptTDES(ticketToBob, bobKeySpec, bobKeyivSpec);
            StringTokenizer tokenizer = new StringTokenizer(ticketToBobDecrypted, ";");
            String ABKey = tokenizer.nextToken();
            String idAliceRcd = tokenizer.nextToken();

            System.out.println("ABKey: " + ABKey);

            //verify the identity of Alice and send message 4 to Alice
            if (idAliceRcd.equals(idAlice)) {
                final byte[] ABKeyBytes = ABKey.getBytes();
                final SecretKeySpec ABKeySpec = new SecretKeySpec(ABKeyBytes, "TripleDES");
                final byte[] ABKeyiv = "C76mb5h9".getBytes();
                final IvParameterSpec ABKeyivSpec = new IvParameterSpec(ABKeyiv);

                String n2 = tDESSecurity.DecryptTDES(n2encrypted,ABKeySpec, ABKeyivSpec);
                System.out.println("n2 generated is: " + n2);
                long n2Updated = Long.parseLong(n2) - 1;
                long n3 = tDESSecurity.giveRandom();

                //generate message 4
                String message4p1 = tDESSecurity.EncryptTDES( String.valueOf(n2Updated),ABKeySpec, ABKeyivSpec);
                String message4p2 = tDESSecurity.EncryptTDES( String.valueOf(n3),ABKeySpec, ABKeyivSpec);
                System.out.println("message4 encrypted, in hexadecimal is: \n");
                for(byte b :(message4p1+message4p2).getBytes())
                {System.out.print(String.format("%02X ",b));}
                pw.println(message4p1+";"+message4p2);

                //Trudy aka Alice initiates a new connect to Bob on this new port number.
                ServerSocket ssocketAlice = new ServerSocket(1233);
                Socket socketALice = ssocketAlice.accept();
                System.out.println("Connected to Trudy aka Alices dupe.");
                BufferedReader br2 = new BufferedReader(new InputStreamReader(socketALice.getInputStream()));
                PrintWriter pw2 = new PrintWriter(socketALice.getOutputStream(), true);
    
                System.out.println("Bob receives KAB{N2-1,N3} and is expected to send back KAB{N3-1}.");
                String message4new = br2.readLine();
                StringTokenizer tokenizer2 = new StringTokenizer(message4new, ";");
                tokenizer2.nextToken();
                String n3encrypted = tokenizer2.nextToken();
                String n3new = tDESSecurity.DecryptTDES(n3encrypted, ABKeySpec, ABKeyivSpec);
                String n3newupdated = tDESSecurity.EncryptTDES(String.valueOf(Long.parseLong(n3new)-1), ABKeySpec, ABKeyivSpec);
                
                //Bob computes the vlaue of KAB{N3-1} and sends it back to Alice.
                System.out.println("Bob computes the vlaue of KAB{N3-1} and sends it back to Alice.");
                pw2.println(n3newupdated);

                //Trudy instantaneously sends back this new value over the initial channel and gets himself authenticated as Alice.
                String trudyN3 = br.readLine();
                System.out.println("message5 encrypted, in hexadecimal is: \n");
                for(byte b :(trudyN3).getBytes())
                {System.out.print(String.format("%02X ",b));}
                String trudyN3Decrypted = tDESSecurity.DecryptTDES(trudyN3, ABKeySpec, ABKeyivSpec);
                if(Long.parseLong(trudyN3Decrypted)+1 == n3)
                {
                    System.out.println("N3-1 and N3 is verified at Bob. Reflection was successful.");
                }

                //Initiating a reattempt of the reflection attack using CBC instead of ECB.
                System.out.println("\nInitiating a reattempt of the reflection attack using CBC instead of ECB.");
                String message4CBC = tDESSecurity.EncryptTDES(String.valueOf(n2Updated)+String.valueOf(n3), ABKeySpec, ABKeyivSpec);

                //Trudy aka Alice sends new challenge to obtain the value of Kab{N3-1} just like he did in case of ECB scenario.
                pw.println(message4CBC);
                String message4CBCnew = br2.readLine();
                System.out.println("message4 encrypted CBC, in hexadecimal is: \n");
                for(byte b :(message4CBCnew).getBytes())
                {System.out.print(String.format("%02X ",b));}
                byte[] message4CBCbytes = Base64.getDecoder().decode(message4CBCnew);
                byte[] message4trimmed = Arrays.copyOfRange(message4CBCbytes, 20, message4CBCbytes.length);
                System.out.println("Message 4 trimmed: "+message4trimmed);
                System.out.println("\nBob was unable to resolve the value of N3 as the protocol used was CBC in TripleDES. Reflection attack has failed. Printing the exceptions:");
                String message4trimmeddecrypted = tDESSecurity.DecryptTDES(new String(message4trimmed), ABKeySpec, ABKeyivSpec);
                
                //Alice responds with Bob's value of Kab{N3-1} computed from Alice's attempt and since it is invalid, the authentication fails and results in an exception.
                try{
                    long n3cbc = Long.parseLong(message4trimmeddecrypted) - 1;
                    pw2.println(tDESSecurity.EncryptTDES(String.valueOf(n3cbc), ABKeySpec, ABKeyivSpec));
                    System.out.println("message5CBC encrypted, in hexadecimal is: \n");
                    for(byte b :(tDESSecurity.EncryptTDES(String.valueOf(n3cbc), ABKeySpec, ABKeyivSpec)).getBytes())
                    {System.out.print(String.format("%02X ",b));}    
                    String n3fail = br.readLine();

                    if(n3 != Long.parseLong(n3fail))
                    {
                        System.out.println("N3-1 and N3 verification failed at Bob. Reflection was unsuccessful.");
                    }
                    else
                    {
                        System.out.println("Your implementation failed, Hemanth!");
                    }

                }
                catch(Exception e)
                {
                    System.out.println("Using CBC saved us from authenticating Alice's dupe.");
                    System.out.println("An exception arises as the received Kab{N3} extracted by Trudy does not make sense to the algorithm as it is simply a trimmed encrypted string.");
                    System.out.println("In continuation, due to the result of the first exception, the resulted decrypted string cannot be convert to a long.");
                }
                //close all open connections
                server.close();
                serverSocket.close();
                ssocketAlice.close();
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    
}
