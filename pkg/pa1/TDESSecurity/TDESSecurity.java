package TDESSecurity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class TDESSecurity {

    //Encrypt using TripleDES and encode to ensure that the special characters can be converted to strings.
    public String EncryptTDES(String nb, SecretKeySpec abKeySpec, IvParameterSpec abKeyivSpec) {
        String nbEncoded = "";
        try {
            Cipher encryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, abKeySpec, abKeyivSpec);
            byte[] nbBytes = String.valueOf(nb).getBytes(StandardCharsets.UTF_8);
            byte[] nbEncryptedBytes = encryptCipher.doFinal(nbBytes);
            nbEncoded = Base64.getEncoder().encodeToString(nbEncryptedBytes);
            return nbEncoded;
        } catch (Exception e) {
            e.printStackTrace();
            return nbEncoded;
        }
    }

    //Decode the string reeived to convert it into the encrypted value and decrypt using TripleDES
     public String DecryptTDES(String nbEncoded, SecretKeySpec abKeySpec, IvParameterSpec abKeyivSpec) {
        String nbDecoded = "";
        try {
            byte[] nbEncryptedBytes = Base64.getDecoder().decode(nbEncoded);
            Cipher decryptCipher = Cipher.getInstance("TripleDES/CBC/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, abKeySpec, abKeyivSpec);
            byte[] nbDecryptedBytes = decryptCipher.doFinal(nbEncryptedBytes);
            nbDecoded = new String(nbDecryptedBytes, StandardCharsets.UTF_8);
            return nbDecoded;
        } catch (Exception e) {
            System.out.println("The decryption failed due to improper format. Returning empty string. More details on why the decryption failed: " + e.getMessage() );
            return nbDecoded;
        }
    }

    //returns a 64bit nounce
    public long giveRandom() {
        Random rand = new Random();
        long nb = rand.nextLong();
        return nb;
    }

    //returns 24 byte key which will be used by KDC to generate session keys
    public String giveRandomKey() {
        SecureRandom randomKey = new SecureRandom();
        byte[] randomKeyBytes = new byte[32];
        randomKey.nextBytes(randomKeyBytes);
        String randomKeyString = Base64.getUrlEncoder().withoutPadding().encodeToString(randomKeyBytes);
        return randomKeyString.substring(0, Math.min(randomKeyString.length(), 24));
    }

    //converts byte array to long
    public long convertToLong(byte[] bytes)
    {
        long value = 0;
        for (byte b : bytes) {
            value = (value << 8) + (b & 255);
        }
        return value;
    }

    //Converts byte array to long array
    public long[] convertByteArrayToLongArray(byte[] bytes) {
        if (bytes == null)
            return null;
        int count = bytes.length / 8;
        long[] longArray = new long[count];
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        for (int i = 0; i < count; i++) {
            longArray[i] = byteBuffer.getLong();
        }
        return longArray;
    }
}
