# Needham-Schroeder
The goal of your programming assignment is to build the extended Needham Schroeder Mediated-Authentication Scheme.

You need to write socket programs that run on three nodes (can be three processes on the same machine), Alice, Bob, and the KDC. You must use Java for your programs. Assume that Alice initiates the authentication exchange. Please ensure the following.
• The challenges are at 64 bits long.
• The secret key encryption scheme is 3DES.
• You need to set up shared keys for each 3DES based secure communication between
two parties (Alice and KDC, Bob and KDC, and, Alice and Bob).
• Use a unique number for identifying a user instead of IP addresses and port numbers.
• Choose a good random number generator for the various nonces (Ns) in the protocol.

When the initial two-message handshake is not used, and when NB is removed from the ticket, the extended version of Needham Schroeder reduces to the original version. For the original version of Needham Schroeder scheme first use the Electronic Code Book (ECB) for encrypting multiple blocks and demonstrate how Trudy is successful in impersonating Alice by causing a reflection attack. Remove this vulnerability by using Cipher Block Chaining (CBC) instead of ECB. In creating the reflection attack (the last three messages), assume that Trudy knows the ticket (i.e., you do not need to show how Trudy manages to get the ticket).

Note: It is recommeded that you pass the byte array to encrypt and decrypted messages instead of passing strings. I realized it too late and was not able to make changes. The encryption and decryption is occurring in EncryptTDES and DecryptTDES functions respectively.

The code files are present in "...\pkg\pa1" and the "...\pkg\pa1\TDESSecurity" contains the package that I imported in my files to reuse the code.

Files in "...\pkg\pa1":
-----------------------
Alice.java -> This file represents Alice and her behavior for the Extended Needham-Schroeder Protocol.
Bob.java -> This file represents Bob and his behavior for the Extended Needham-Schroeder Protocol.
KDC.java -> This file represents KDC's behavior for the Extended Needham-Schroeder Protocol.

AliceReflection.java -> This file represents Alice and her behavior for the reflection attack on original Needham-Schroeder Protocol with the use of ECB and CBC.
BobReflection.java -> This file represents Bob and his behavior for the reflection attack on original Needham-Schroeder Protocol with the use of ECB and CBC.
KDCReflection.java -> This file represents KDC's behavior for the reflection attack on original Needham-Schroeder Protocol with the use of ECB and CBC.

Files in "...\pkg\pa1\TDESSecurity":
------------------------------------
TDESSecurity.java -> This file contains the reusable code used in the project.

Files in current folder:
------------------------
Extended Needham-Schroeder Protocol Outputs.pdf -> Outputs from running Bob.java, KDC.java and Alice.java.
Reflection Attack ECB and CBC.pdf -> Outputs from running BobReflection.java, KDCReflection.java and AliceReflection.java.


To implement Extended Needham-Schroeder Protocol:
> Navigate to "...\pkg\pa1" folder and import the folder into IDE.
> First run Bob.java
> Next, run KDC.java
> Next, run Alice.java

To implement Reflection on Needham-Schroeder Protocol:
> Navigate to "...\pkg\pa1" folder and import the folder into IDE.
> First run BobReflection.java
> Next, run KDCReflection.java
> Next, run AliceReflection.java
