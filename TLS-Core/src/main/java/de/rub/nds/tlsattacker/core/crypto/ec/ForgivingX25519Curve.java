/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

/**
 * An Implementation of X25519 which does not care if the private key does not
 * have the correct format
 */
public class ForgivingX25519Curve {

    private static final Logger LOGGER = LogManager.getLogger();

    public static final int ELEMENT_SIZE = 32;

    /**
     * Private constructor to prevent instantiation
     */
    private ForgivingX25519Curve() {
    }

    /**
     * Generates a publicKey for a given private key. The key is truncated or
     * padded to the correct size if necessary
     *
     * @param privateKey
     *            The private key to use
     * @return publickey The computed public key
     */
    public static byte[] computePublicKey(BigInteger privateKey) {
        return computePublicKey(privateKey.toByteArray());
    }

    /**
     * Generates a publicKey for a given private key. The key is truncated or
     * padded to the correct size if necessary
     *
     * @param privateKey
     *            The private key to use
     * @return publickey The computed public key
     */
    public static byte[] computePublicKey(byte[] privateKey) {
        X25519.precompute();
        if (privateKey.length > ELEMENT_SIZE) {
            LOGGER.debug("privatekey has is longer than " + ELEMENT_SIZE + " bytes. Using only first " + ELEMENT_SIZE
                    + " bytes.");
            privateKey = Arrays.copyOfRange(privateKey, 0, ELEMENT_SIZE);
        } else if (privateKey.length < ELEMENT_SIZE) {
            LOGGER.debug("privatekey has is shorter than " + ELEMENT_SIZE + " bytes. Padding with 0x00...");
            privateKey = Arrays.copyOf(privateKey, ELEMENT_SIZE);
        }
        byte[] publicKey = new byte[ELEMENT_SIZE];
        X25519.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    /**
     * Computes a shared point/secret from a private key and a publickey
     *
     * @param privateKey
     *            Our side's private key
     * @param publicKey
     *            The other sides public key
     * @return A shared secret computed with the private and public key
     */
    public static byte[] computeSharedSecret(BigInteger privateKey, byte[] publicKey) {
        return computeSharedSecret(privateKey.toByteArray(), publicKey);
    }

    /**
     * Computes a shared point/secret from a private key and a publickey
     *
     * @param privateKey
     *            Our side's private key
     * @param publicKey
     *            The other sides public key
     * @return A shared secret computed with the private and public key
     */
    public static byte[] computeSharedSecret(byte[] privateKey, byte[] publicKey) {
        if (privateKey.length > ELEMENT_SIZE) {
            LOGGER.debug("privatekey is longer than " + ELEMENT_SIZE + " bytes. Using only first " + ELEMENT_SIZE
                    + " bytes.");
            privateKey = Arrays.copyOfRange(privateKey, 0, ELEMENT_SIZE);
        } else if (privateKey.length < ELEMENT_SIZE) {
            LOGGER.debug("privatekey is shorter than " + ELEMENT_SIZE + " bytes. Padding with 0x00...");
            privateKey = Arrays.copyOf(privateKey, ELEMENT_SIZE);
        }
        if (publicKey.length > ELEMENT_SIZE) {
            LOGGER.debug("publicKey is longer than " + ELEMENT_SIZE + " bytes. Using only first " + ELEMENT_SIZE
                    + " bytes.");
            publicKey = Arrays.copyOfRange(publicKey, 0, ELEMENT_SIZE);
        } else if (publicKey.length < ELEMENT_SIZE) {
            LOGGER.debug("publicKey is shorter than " + ELEMENT_SIZE + " bytes. Padding with 0x00...");
            publicKey = Arrays.copyOf(publicKey, ELEMENT_SIZE);
        }
        byte[] sharedSecret = new byte[ELEMENT_SIZE];
        X25519.scalarMult(privateKey, 0, publicKey, 0, sharedSecret, 0);
        return sharedSecret;
    }
}
