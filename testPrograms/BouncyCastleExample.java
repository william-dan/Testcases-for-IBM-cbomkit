/*
 * Simple BouncyCastle example: generate RSA keypair, sign a message, and verify the signature.
 *
 * Compile (example using bcprov jar):
 *   1) Download BouncyCastle provider JAR (e.g. bcprov-jdk15on-1.76.jar) from Maven Central:
 *      https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.76/
 *   2) From project root, compile:
 *      javac -cp /path/to/bcprov-jdk15on-1.76.jar testPrograms/BouncyCastleExample.java
 *   3) Run:
 *      java -cp testPrograms:/path/to/bcprov-jdk15on-1.76.jar BouncyCastleExample
 *
 * Notes:
 * - The example uses the BouncyCastle provider explicitly ("BC"). Make sure the bcprov jar matches the Java version.
 * - Adjust the jar path and version as needed.
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleExample {
    public static void main(String[] args) throws Exception {
        // Register BouncyCastle as a provider
        Security.addProvider(new BouncyCastleProvider());

        // Generate RSA key pair (2048 bits)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        String message = "Hello, BouncyCastle!";
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        // wait for input
        System.out.println("Press Enter to continue...");
        System.in.read();

        // Sign the message using SHA256withRSA
        Signature signer = Signature.getInstance("SHA256withRSA", "BC");
        signer.initSign(kp.getPrivate());
        signer.update(msgBytes);
        byte[] signature = signer.sign();

        String sigB64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Message: " + message);
        System.out.println("Signature (Base64): " + sigB64);

        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withRSA", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(msgBytes);
        boolean valid = verifier.verify(signature);
        System.out.println("Signature valid: " + valid);
    }
}
