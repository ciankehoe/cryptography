/*
CA4005 - Cryptography and Security Protocols
Assignment 1: Symmetric File Encryption Using Password and Salt
Created: 20/10/2021

Author : Cian Kehoe
Email : cian.kehoe34@mail.dcu.ie
Student ID : 18426852
*/

package assignment_01;

import java.util.*;
import java.io.FileInputStream;
import java.io.File;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Assignment1 implements Assignment1Interface {

    private static final int AESBlockSizeBytes = 16; // AES blocksize in bytes : 16 bytes -> 128 bits
    private static final int rsaExponent = 65537;
    private static final String psswd = "h#$>cyD:-}3:M#T7";
    private static final BigInteger mod = new BigInteger("c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9", 16);

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Assignment1 encrypter = new Assignment1();
        byte[] psswdBytes = psswd.getBytes();

        // first check to see if the program was run with required clarg
        byte[] inputFile = readFile(args[0]);

        // generate salt
        byte[] salt = generate128bitValue();
        
        // generate k (H^200(password||salt)) with SHA256
        byte[] key = encrypter.generateKey(psswdBytes, salt);
        
        // generate Initialization Vector (IV / i)
        byte[] IV = generate128bitValue();

        // AES encryption
        byte[] encryptedFile = encrypter.encryptAES(inputFile, IV, key);
        // System.out.println("AES Encrypted File (Hex): + "byteArrayToHex(encryptedFile));

        byte[] rsaEncryptedPW = encrypter.encryptRSA(psswdBytes, BigInteger.valueOf(rsaExponent), mod);
        //System.out.println("RSA Encrypted Password (Hex): " + byteArrayToHex(result));

        byte[] decryptedFile = encrypter.decryptAES(encryptedFile, IV, key);
        // System.out.println(removePadding(decryptedFile)); // decrypted & unpadded text

        // perform all file writes
        writeFile(byteArrayToHex(salt), "Salt.txt");
        writeFile(byteArrayToHex(IV), "IV.txt");
        writeFile(byteArrayToHex(rsaEncryptedPW), "Password.txt");
        //writeFile(byteArrayToHex(encryptedFile), "Encryption.txt");

        System.out.print(byteArrayToHex(encryptedFile));
    }

    /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */

    public byte[] generateKey(byte[] password, byte[] salt) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream concatStream = new ByteArrayOutputStream();

        concatStream.write(password);
        concatStream.write(salt);

        // generate 256-bit AES key (k) -> run sha-256 on concatenated password+salt 200x
        byte[] aesKey = sha256(concatStream.toByteArray());

        return aesKey;
    }

    /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */

    public byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) throws GeneralSecurityException {
        // setup
        Cipher encryption = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // pad plaintext
        // paddingSize refers to bytes
        int paddingSize = AESBlockSizeBytes - (plaintext.length % AESBlockSizeBytes);
        byte[] arrayForPadding = new byte[plaintext.length + paddingSize];

        // copy in plaintext byte array
        System.arraycopy(plaintext, 0, arrayForPadding, 0, plaintext.length);
        // pad new array
        arrayForPadding[plaintext.length] = (byte) 128;

        // perform encryption
        encryption.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        // doFinal encrypts or decrypts data in a single-part operation
        byte[] cipherText = encryption.doFinal(arrayForPadding);

        return cipherText;
    }
    
    /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
    
    public byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        
        byte[] plainText = cipher.doFinal(ciphertext);


        return plainText;
    }
            
    /* 
    Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus.
    We will be encrypting the password (p) specifically.
    */
    public byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus) {
        BigInteger password = new BigInteger(plaintext);

        BigInteger modExpResult = modExp(password, exponent, modulus);
        byte[] rsaResult = convertBigIntegerToByteArray(modExpResult);

        return rsaResult;
    }
 
    /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */

    public BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus) {
        /////////////////////////////////////////////////////////////////////
        // square and multiply algorithm - right -> left variant (used) /////
        /////////////////////////////////////////////////////////////////////
        /* y = 1
           for i = 0 to k - 1 do
               if xi = 1 then y = (y*a) mod n end if
               a = (a*a) mod n
            end for
        */

        BigInteger y = BigInteger.valueOf(1);

        for (int i=0; i < exponent.bitLength(); i++) {
            // testBit() - Returns true if and only if the designated bit is set
            if (exponent.testBit(i)) {
                y = y.multiply(base).mod(modulus);
            }
            base = base.multiply(base).mod(modulus);
        }
        return y;

        /////////////////////////////////////////////////////////////////////////
        // square and multiply algorithm - left -> right variant (not-used) /////
        /////////////////////////////////////////////////////////////////////////
        /* y = 1
        for i = k-1 downto 0 do
            y = (y*y) mod n
            if xvi = 1 then y = (y*a) mod n end if
        end for

        BigInteger y = BigInteger.valueOf(1);
        for (int i = exponent.bitLength() -1 ; i >= 0; i--) {
            y = y.multiply(y).mod(modulus);
            if (exponent.testBit(i)) {
                y = y.multiply(base).mod(modulus);
            }
        }
        return y;
        */
    }

    // ----------------------------------------------------------------------------
    // -------------------- helper methods ----------------------------------------
    // ----------------------------------------------------------------------------

    // generate Initialisation Vector (IV) & Salt
    private static byte[] generate128bitValue() {
        // SecureRandom -> This class provides a cryptographically strong random number generator (RNG).
        SecureRandom randomGenerated = new SecureRandom();
        byte[] salt = new byte[16];
        randomGenerated.nextBytes(salt);
        return salt;
    }

    private static String byteArrayToHex(byte[] bta) {
        StringBuilder hexRepr = new StringBuilder();
        for (byte b : bta) {
            char[] hexDigits = new char[2];
            hexDigits[0] = Character.forDigit((b >> 4) & 0xF, 16);
            hexDigits[1] = Character.forDigit((b & 0xF), 16);
            hexRepr.append(hexDigits);
        }
        return hexRepr.toString();
    }

    // perform SHA256 hashing 200x
    private static byte[] sha256(byte[] keyToHash) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        for(int i = 0; i < 200; i++) {
            keyToHash = digest.digest(keyToHash);
        }
        return keyToHash;
    }

    // custom conversion -> replace BigInteger.toByteArray()
    private static byte[] convertBigIntegerToByteArray(BigInteger x) {
        byte[] xBytes = x.toByteArray();
        if (xBytes[0] == 0) {
            xBytes = Arrays.copyOfRange(xBytes, 1, xBytes.length);
        }
        return xBytes;
    }

    // remove padding from ciphertext decrypted byte[]
    private static String removePadding(byte[] padded) {
        String depaddedString = "";
        if (null != byteArrayToHex(padded) && byteArrayToHex(padded).length() > 0 ) {
            int lastOccurence = byteArrayToHex(padded).lastIndexOf("8");
            // check validity
            if (lastOccurence != -1) {
                depaddedString = byteArrayToHex(padded).substring(0, lastOccurence);
            }
        }
        return depaddedString;
    }

    private static byte[] readFile(String arg) {
        try {
            InputStream inputStream = new FileInputStream(arg);

            long fileSize = new File(arg).length();
    
            // file contents stored here
            byte[] plaintext = new byte[(int) fileSize];
            inputStream.read(plaintext);
            inputStream.close();

            return plaintext;
        } catch (IOException exception) {
            System.out.println("Usage: java Assignment1 <fileName>");
            System.exit(1);
        }
        return null;
    }

    private static void writeFile(String s, String filename) {
        try {
            FileWriter writer = new FileWriter(filename);
            writer.write(s); 
            writer.flush();
            writer.close();
            
        } catch (IOException exception) {
            exception.printStackTrace();
            System.exit(1);
        }
    }
}