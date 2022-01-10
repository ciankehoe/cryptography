package assignment_02;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

	interface Assignment2Interface {
	 
        /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */
        
		BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus);
		
        /* Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus */
           
		BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus);
		
        /* Method generateS generates the second part of the ElGamal signature from the given plaintext, secretKey, first signature part r, random value k and modulus */
           
        BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus) throws GeneralSecurityException, Exception;
        
        /* Method calculateGCD returns the GCD of the given val1 and val2 */
        
        BigInteger calculateGCD(BigInteger val1, BigInteger val2);
				
        /* Method calculateInverse returns the modular inverse of the given val using the given modulus */
        
        BigInteger calculateInverse(BigInteger val, BigInteger modulus) throws Exception;
	 
	}

