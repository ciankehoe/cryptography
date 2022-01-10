package assignment_02;

import java.util.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Assignment2 implements Assignment2Interface {
    public static void main(String[] args) throws Exception {

        /*-------------------------------- Elgamal Signature Scheme --------------------------------*/
        Assignment2 elgamal = new Assignment2();

        // file input - read as argument
        byte[] fileToSign = readFile(args[0]);

        // prime modulus (p)
        BigInteger primeMod = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        
        // generator (g)
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

        // generate (random ephemeral) secret key : 1 < x < (p - 1)
        BigInteger secretKeyX = generateRandomKey(primeMod);

        // compute public key y
        BigInteger publicKeyY = elgamal.generateY(g, secretKeyX, primeMod);

        // The pair (r||s) is the digital signature of m
        // initialize r, s values
        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;

        while (s.compareTo(BigInteger.ZERO) == 0) {
            BigInteger randK;
            // sign a message (m)
            do {
                randK = generateRandomKey(primeMod);
            } while (!(elgamal.calculateGCD(randK, primeMod.subtract(BigInteger.ONE)).equals(BigInteger.ONE)));
            
            r = elgamal.generateR(g, randK, primeMod);

            s = elgamal.generateS(fileToSign, secretKeyX, r, randK, primeMod);
        }


        /*-------------------------------- VERIFICATION CHECKS --------------------------------*/
        // verify : 0 < r < p
        boolean rGTZero = r.compareTo(BigInteger.ZERO)  == 1;
        boolean rLTP = r.compareTo(primeMod) == -1;
        boolean verifyR = rGTZero && rLTP;
        

        // verify : 0 < s < p-1
        boolean sGTZero = s.compareTo(BigInteger.ZERO)  == 1;
        boolean sLTPMinusOne = s.compareTo(primeMod.subtract(BigInteger.ONE)) == -1;
        boolean verifyS = sGTZero && sLTPMinusOne;
        

        // g^H(m) (mod p) = y^r*r^s (mod p)
        // v1 = g^H(m) (mod p)
        // v2 = y^r*r^s (mod p)
        BigInteger hashedMessage = new BigInteger(sha256(fileToSign));
        // checking v1 == v2
        boolean signatureVerificaton = (g.modPow(hashedMessage, primeMod)).equals(((publicKeyY.modPow(r, primeMod)).multiply(r.modPow(s, primeMod))).mod(primeMod));

        /*-------------------------------- PRINTING --------------------------------*/

        System.out.println("-------------------------------- Generated Values --------------------------------");
        System.out.println("Secret Key (x) : " + secretKeyX);
        System.out.println("Public Key (y) : " + publicKeyY);
        System.out.println("r : " + r);
        System.out.println("s : " + s);

        System.out.println("-------------------------------- Verification --------------------------------");
        System.out.println("(0 < r < p) : " + verifyR);
        System.out.println("(0 < s < p-1) : " + verifyS);
        System.out.println("g^H(m) (mod p) = y^r*r^s (mod p) : " + signatureVerificaton);

        /*-------------------------------- FILE WRITING --------------------------------*/

        writeFile(convertByteArrayToHex(convertBigIntegerToByteArray(publicKeyY)), "y.txt");
        writeFile(convertByteArrayToHex(convertBigIntegerToByteArray(r)), "r.txt");
        writeFile(convertByteArrayToHex(convertBigIntegerToByteArray(s)), "s.txt");
    }

    /* Method generateY returns the public key y and is generated from the given generator, secretKey  and modulus */
    
    public BigInteger generateY(BigInteger generator, BigInteger secretKey, BigInteger modulus) {
        // y = gx (mod p)
        return generator.modPow(secretKey, modulus);
    }
    
    /* Method generateR generates the first part of the ElGamal signature from the given generator, random value k and modulus */
        
    public BigInteger generateR(BigInteger generator, BigInteger k, BigInteger modulus) {
        return generator.modPow(k, modulus);
    }
    
    /* Method generateS generates the second part of the ElGamal signature from the given plaintext, secretKey, first signature part r, random value k and modulus */
        
    public BigInteger generateS(byte[] plaintext, BigInteger secretKey, BigInteger r, BigInteger k, BigInteger modulus) throws Exception {
        // get sha256 hashed message (H(m))
        BigInteger hashedMessage = new BigInteger(sha256(plaintext));
        // H(m) - xr where secretKey -> x
        // first tmp section of computation for s
        BigInteger tmpS = hashedMessage.subtract(secretKey.multiply(r));
        
        // get multiplicative inverse of k
        BigInteger inverseK = BigInteger.valueOf(-1);
        do {
            inverseK = calculateInverse(k, modulus.subtract(BigInteger.ONE));
        } while (inverseK.equals(BigInteger.valueOf(-1)));
        
        // (H(m) - xr)k^-1
        tmpS = tmpS.multiply(inverseK);
        // s = (H(m) - xr)k^-1 (mod p-1)
        BigInteger s = tmpS.mod(modulus.subtract(BigInteger.ONE));
        return s;
    }
    
    /* Method calculateGCD returns the GCD of the given val1 and val2 */
    // GCD --> Greatest Common Divisor
    // check that k and p-1 are relatively prime
    // they must be relatively prime as any a in Zn has a unique inverse 
    // modulo n IF AND ONLY IF a and n are relatively prime
    // i.e a and n, gcd(a, n) = 1.
    public BigInteger calculateGCD(BigInteger val1, BigInteger val2) {
        // val1 = k
        // val2 = p-1
        if (val2.equals(BigInteger.ZERO)) {
            return val1;
        }
        return calculateGCD(val2, val1.mod(val2));
    }
            
    /* Method calculate(Multiplicative)Inverse returns the modular inverse of the given val using the given modulus */
    // XGCD require here
    public BigInteger calculateInverse(BigInteger val, BigInteger modulus) throws Exception {
        BigInteger[] xgcdResult = extendedGCD(val, modulus);

        // if it's != 1, then there is NO multiplicative inverse
        if (!xgcdResult[0].equals(BigInteger.ONE)) {
            return BigInteger.valueOf(-1);
        }

        // check if greater than 0
        if ((xgcdResult[1].compareTo(BigInteger.ZERO)) == 1) {
            return xgcdResult[1];
        } else {
            return xgcdResult[1].add(modulus);
        }
    }
    
    // Extended GCD --> compute x and y such that ax + by = gcd(a,b)
    // The XGCD takes as input a and b and outputs x, y, rk such that: rk = gcd(a,b) = xa + yb 
    // Resource Utilized : https://introcs.cs.princeton.edu/java/99crypto/ExtendedEuclid.java.html
    private static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[] { a, BigInteger.ONE, BigInteger.ZERO };
        }
        BigInteger[] result = extendedGCD(b, a.mod(b));
        BigInteger x = result[2];
        BigInteger y = result[1].subtract((a.divide(b)).multiply(x));
        BigInteger Rk = result[0];
        
        return new BigInteger[] { Rk, x, y };
    }

    // using to generate secret key (x) and random ephemeral key (k)
    // originally two separate methods but performing same gen
    // generate value : 0 < value < p - 1
    // where value is x, or k and p is the prime modulus
    private static BigInteger generateRandomKey(BigInteger p) {
        SecureRandom ranNumGen = new SecureRandom();
        BigInteger randVal;
        do {
            randVal = new BigInteger(p.bitLength(), ranNumGen);
        } while (!((randVal.compareTo(BigInteger.ZERO)) > 0) && (randVal.compareTo(p.subtract(BigInteger.ONE)) < 0));
        return randVal;
    }

    private static byte[] sha256(byte[] inputToHash) throws NoSuchAlgorithmException {
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        return sha256Digest.digest(inputToHash);
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
            System.out.println("Usage: java Assignment2 <fileToSign>");
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

    // custom conversion -> replace BigInteger.toByteArray()
    private static byte[] convertBigIntegerToByteArray(BigInteger x) {
        byte[] xBytes = x.toByteArray();
        if (xBytes[0] == 0) {
            xBytes = Arrays.copyOfRange(xBytes, 1, xBytes.length);
        }
        return xBytes;
    }

    private static String convertByteArrayToHex(byte[] bta) {
        StringBuilder hexRepr = new StringBuilder();
        for (byte b : bta) {
            char[] hexDigits = new char[2];
            hexDigits[0] = Character.forDigit((b >> 4) & 0xF, 16);
            hexDigits[1] = Character.forDigit((b & 0xF), 16);
            hexRepr.append(hexDigits);
        }
        return hexRepr.toString();
    }
}
