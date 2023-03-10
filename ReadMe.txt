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