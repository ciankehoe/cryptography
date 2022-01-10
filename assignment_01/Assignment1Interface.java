package assignment_01;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

	interface Assignment1Interface {
	 
        /* Method generateKey returns the key as an array of bytes and is generated from the given password and salt. */
        
		byte[] generateKey(byte[] password, byte[] salt) throws IOException, NoSuchAlgorithmException;
		
        /* Method encryptAES returns the AES encryption of the given plaintext as an array of bytes using the given iv and key */
           
		byte[] encryptAES(byte[] plaintext, byte[] iv, byte[] key) throws GeneralSecurityException;
		
        /* Method decryptAES returns the AES decryption of the given ciphertext as an array of bytes using the given iv and key */
        
        byte[] decryptAES(byte[] ciphertext, byte[] iv, byte[] key) throws GeneralSecurityException;
				
        /* Method encryptRSA returns the encryption of the given plaintext using the given encryption exponent and modulus */
        
        byte[] encryptRSA(byte[] plaintext, BigInteger exponent, BigInteger modulus);
	 
        /* Method modExp returns the result of raising the given base to the power of the given exponent using the given modulus */
        
        BigInteger modExp(BigInteger base, BigInteger exponent, BigInteger modulus);
        
	}