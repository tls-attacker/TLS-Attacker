/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Implements the HMAC class */
public class HMAC {

    private static final Logger LOGGER = LogManager.getLogger();
    private byte[] opad;
    private byte[] ipad;
    private byte[] secret;
    private MacAlgorithm macAlgorithm;
    private MessageDigest digest;

    /**
     * Creates an hmac instance.
     *
     * @param macAlgorithm sets the hash algorithm that is going to be used for the HMAC computation
     */
    public HMAC(MacAlgorithm macAlgorithm) throws NoSuchAlgorithmException {
        this.macAlgorithm = macAlgorithm;

        // decides which hash for the hmac should be used
        switch (macAlgorithm) {
            case HMAC_SHA1:
                this.digest = MessageDigest.getInstance("SHA-1");
                break;
            case HMAC_MD5:
                this.digest = MessageDigest.getInstance("MD5");
                break;
            case HMAC_SHA256:
                this.digest = MessageDigest.getInstance("SHA-256");
                break;
            case HMAC_SHA384:
                this.digest = MessageDigest.getInstance("SHA-384");
                break;
            case HMAC_GOSTR3411:
                this.digest = MessageDigest.getInstance("GOST3411");
                break;
            case HMAC_GOSTR3411_2012_256:
                this.digest = MessageDigest.getInstance("GOST3411-2012-256");
                break;
            default:
                throw new UnsupportedOperationException("Hash algorithm is not supported");
        }
    }

    /**
     * Initializes the hmac with a secret and data that is to be hashed later on. It also makes sure
     * that the key, the ipad and opad have the same length by padding.
     *
     * @param secret the hmac key
     */
    public void init(byte[] secret) throws NoSuchAlgorithmException {
        if (secret == null) {
            LOGGER.warn(
                    "Secret is null! Continuing to init hmac with a secret set to zero bytes...");
            secret = new byte[0];
        }
        switch (this.macAlgorithm) {
            case HMAC_SHA1:
            case HMAC_MD5:
            case HMAC_SHA256:
            case HMAC_GOSTR3411_2012_256:
                this.secret = padding(secret, 64, (byte) 0x00);
                this.opad = padding(new byte[0], 64, (byte) 0x5C);
                this.ipad = padding(new byte[0], 64, (byte) 0x36);
                break;

            case HMAC_SHA384:
                this.secret = padding(secret, 128, (byte) 0x00);
                this.opad = padding(new byte[0], 128, (byte) 0x5C);
                this.ipad = padding(new byte[0], 128, (byte) 0x36);
                break;

            case HMAC_GOSTR3411:
                this.secret = padding(secret, 32, (byte) 0x00);
                this.opad = padding(new byte[0], 32, (byte) 0x5C);
                this.ipad = padding(new byte[0], 32, (byte) 0x36);
                break;
            default:
                LOGGER.warn("Undefined MAC Algorithm");
                this.secret = secret;
                this.opad = new byte[0];
                this.ipad = new byte[0];
        }
    }

    /**
     * Computes the hmac and returnes it.
     *
     * @param data
     * @return the computed hmac of the hmac instance
     * @throws NoSuchAlgorithmException
     */
    public byte[] doFinal(byte[] data) throws NoSuchAlgorithmException {
        // hmac = hmac_<hash>(<hash>(secret XOR opad) || <hash>(secret XOR ipad || data))
        byte[] hash =
                this.digest.digest(
                        ArrayConverter.concatenate(xorBytes(this.secret, this.ipad), data));
        return this.digest.digest(
                ArrayConverter.concatenate(xorBytes(this.secret, this.opad), hash));
    }

    /*
     * This function pads a specific byte to a byte array. Has the byte array the same length as the length parameter of
     * the function, the byte array will be returned without padding. Is the byte array bigger than the length
     * parameter, the byte array is hashed and returned.
     */
    private byte[] padding(byte[] bytes, int length, byte pad) throws NoSuchAlgorithmException {
        if (bytes.length < length) {
            byte[] bytesPadded = new byte[length];
            for (int i = 0; i < bytes.length; i++) {
                bytesPadded[i] = bytes[i];
            }
            for (int i = bytes.length; i < (length); i++) {
                bytesPadded[i] = pad;
            }
            return bytesPadded;
        } else if (bytes.length == length) {
            return bytes;
        } else {
            byte[] hash = hash(bytes);
            return padding(hash, length, pad);
        }
    }

    /*
     * XOR's two byte arrays and returns the result
     */
    private byte[] xorBytes(byte[] a1, byte[] a2) {
        byte[] a3 = new byte[a1.length];
        for (int i = 0; i < a1.length; i++) {
            a3[i] = (byte) (a1[i] ^ a2[i]);
        }
        return a3;
    }

    /*
     * Hashes an array of bytes
     */
    private byte[] hash(byte[] bytes) throws NoSuchAlgorithmException {
        return this.digest.digest(bytes);
    }
}
