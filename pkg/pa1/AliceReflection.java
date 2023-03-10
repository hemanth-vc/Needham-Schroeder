import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.StringTokenizer;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import TDESSecurity.TDESSecurity;

public class AliceReflection {
    //Initializing final string idALice and ibBob to identify Alice and Bob. This is known to everyone.
    static final String idALice = new String("8018142327");
    static final String idBob = new String("8019351793");

    //Initializing Alice's private key and declaring the encrypting algorithm as TripleDES. Also declaring the Initializing Vector(iv)
    static final byte[] aliceKey = "7mng65v8jf4lxn93nabf981m".getBytes();
    static final SecretKeySpec aliceKeySpec = new SecretKeySpec(aliceKey, "TripleDES");
    static final byte[] aliceKeyiv = "B76mb5h9".getBytes();
    static final IvParameterSpec aliceKeyivSpec = new IvParameterSpec(aliceKeyiv);

    public static void main(String args[])
    {
        //Common methods are written in TDESSecurity
        TDESSecurity tDESSecurity = new TDESSecurity();

        try {

            System.out.println("AliceReflection has started.");

            //Creating a socket to connect with Alice and KDC
            Socket socket = new Socket("localhost", 1235);
            socket.setSoTimeout(100000);
            System.out.println("Alice established connection with Bob.");

            Socket socketKDC = new Socket("localhost", 1234);
            System.out.println("Alice established connection with KDC.");

            //Creating a bufferreader and printwriter to print to and read from the Bob's socket stream.
            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //Creating a bufferreader and printwriter to print to and read from the KDC socket stream.
            PrintWriter pwKDC = new PrintWriter(socketKDC.getOutputStream(), true);
            BufferedReader brKDC = new BufferedReader(new InputStreamReader(socketKDC.getInputStream()));

            //Alice initiates communicaiton with KDC for session key generation.
            long n1 = tDESSecurity.giveRandom();
            pwKDC.println(String.valueOf(n1));
            pwKDC.println(idALice);
            pwKDC.println(idBob);

            //Alice receives key and ticket details from KDC.
            String ticketDetails = brKDC.readLine();
            String decryptedTicketDetails = tDESSecurity.DecryptTDES(ticketDetails,aliceKeySpec, aliceKeyivSpec);
            StringTokenizer tokenizer = new StringTokenizer(decryptedTicketDetails,";");
            
            String n1Rcd = tokenizer.nextToken();
            String idBobRcd = tokenizer.nextToken();
            String ABKey = tokenizer.nextToken();
            String ticketToBob = tokenizer.nextToken();

            //print the received values to the output console.
            System.out.println("n1: "+n1+" n1 received: "+n1Rcd);
            System.out.println("idBob: "+idBob+" idBob received:"+idBobRcd);
            System.out.println("ABKey: " + ABKey);
            System.out.println("ticketToBob: "+ ticketToBob);

            //set up the session key and start communicating with Bob
            final byte[] ABKeyBytes = ABKey.getBytes();
            final SecretKeySpec ABKeySpec = new SecretKeySpec(ABKeyBytes, "TripleDES");
            final byte[] ABKeyiv = "C76mb5h9".getBytes();
            final IvParameterSpec ABKeyivSpec = new IvParameterSpec(ABKeyiv);
            
            //send message 3 to Bob
            long n2 = tDESSecurity.giveRandom();
            System.out.println("n2 is: "+String.valueOf(n2));
            pw.println(ticketToBob);
            String message3p2 = tDESSecurity.EncryptTDES(String.valueOf(n2),ABKeySpec, ABKeyivSpec);
            pw.println(message3p2);

            //read message4
            String message4 = br.readLine();
            System.out.println("message4: "+message4);
            StringTokenizer tokenizer2 = new StringTokenizer(message4, ";");
            String n2updatedEncrypted = tokenizer2.nextToken();
            String n3encrypted = tokenizer2.nextToken();
            String n2updated = tDESSecurity.DecryptTDES(n2updatedEncrypted, ABKeySpec, ABKeyivSpec);
            System.out.println("n2-1: "+n2updated);

            //verifying and authenticating Trudy with the use of reflection.
            if(Long.parseLong(n2updated)+1 == n2)
            {
                System.out.println("N2 and N2-1 is verified at Alice.");
                System.out.println("Initiating CHEAT mode... Unleashing Trudy!");
                Socket socketTrudy = new Socket("localhost", 1233);
                BufferedReader br2 = new BufferedReader(new InputStreamReader(socketTrudy.getInputStream()));
                PrintWriter pw2 = new PrintWriter(socketTrudy.getOutputStream(), true);
    
                //Trudy used same ticket and starts a new conversation with Bob.
                //While sending message4 Trudy uses data extracted KAB{N3} from the initial connection with Bob.
                System.out.println("Trudy used same ticket and starts a new conversation with Bob.");
                System.out.println("While sending message4 Trudy uses data extracted KAB{N3} from the initial connection with Bob.");
                long n2new = 8562914698219636806L;

                //retrieve Kab{N3-1}
                String message4p1 = tDESSecurity.EncryptTDES( String.valueOf(n2new),ABKeySpec, ABKeyivSpec);
                String message4p2 = n3encrypted;
                System.out.println("message4 encrypted: " + message4p1+message4p2);
                pw2.println(message4p1+";"+message4p2);
                String hackedn3 = br2.readLine();

                //Trudy now uses hackedn3 value and returns it to Bob using the original connenction to authenticate itself as Alice.
                pw.println(hackedn3);

                //Bob now verifies and authenticates Alice. Check Bob's output window.
                System.out.println("Bob now verifies and authenticates Alice. Check Bob's output window.\n");

                //change the protocol to CBC instead of ECB. And reattempt the reflection attack.
                System.out.println("Let us now change the protocol to CBC instead of ECB. And reattempt the reflection attack.");
                String message4CBC = br.readLine();
                System.out.println("message4CBC: "+message4);
                String hackedn3fail ="";
                pw2.println(message4CBC);
            try
            {
                hackedn3fail = br2.readLine();
            }
            catch(Exception e)
            {
                System.out.println("\nReflection attack failed in case of TripleDES with CBC.");
                System.out.println("\nAn exception arises as the characters of Kab{N3} extarcted do not make sense. br.readLine() expects only string objects.");
                System.out.println("More details of why the connection closed: " + e.getMessage());
            }

            pw.println(hackedn3fail);

            //close all open connections
            socket.close();
            socketKDC.close();
            socketTrudy.close();

            }
        }
            catch(Exception e)
            {
                e.printStackTrace();;
            }
    }
    
}
