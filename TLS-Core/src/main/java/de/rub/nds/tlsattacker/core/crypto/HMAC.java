/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


/**
 * HMAC provides a base for implementing the PRF for TLS1.0 and TLS1.2
 * */
public class HMAC {
    private byte[] opad;
    private byte[] ipad;
    private byte[] secret;
    private byte[] data;
    private byte[] hmac;
    private MacAlgorithm macAlgorithm;

    /**
     * Creates an hmac instance.
     *
     * @param macAlgorithm sets the hash algorithm for the prf
     */
    public HMAC(MacAlgorithm macAlgorithm) {
        this.opad = new byte[0];
        this.ipad = new byte[0];
        this.macAlgorithm = macAlgorithm;
    }

    /*Implements getter amd setter methods*/
    public void setSecret(byte[] newSecret) {
        this.secret = newSecret;
    }

    public void setData(byte[] newData) {
        this.data = newData;
    }

    public void setHashAlgorithm(MacAlgorithm macAlgorithm) {
        this.macAlgorithm = macAlgorithm;
    }

    public byte[] getOpad() {
        return this.opad;
    }

    public byte[] getIpad() {
        return this.ipad;
    }

    public byte[] getSecret() {
        return this.secret;
    }

    public byte[] getData() {
        return this.data;
    }

    public byte[] getHmac() {
        return this.hmac;
    }

    public void show(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++)
            System.out.printf("%02X ", bytes[i]);
        System.out.println();
    }

    /**
     * Initializes the hmac with a secret and data that is to be hashed later on.
     * It also makes sure that the key, the ipad and opad have the same length by padding.
     *
     * @param secret the hmac key
     *
     * @param data the data that is going to be hashed
     **/
    public void init(byte[] secret, byte[] data) throws NoSuchAlgorithmException {
        switch (this.macAlgorithm) {
            case HMAC_SHA1:
            case HMAC_MD5:
            case HMAC_SHA256:
            case HMAC_GOSTR3411_2012_256:
                this.secret = padding(secret, 64, (byte) 0x00);
                this.opad = padding(this.opad, 64, (byte) 0x5C);
                this.ipad = padding(this.ipad, 64, (byte) 0x36);
                this.data = data;
                break;

            case HMAC_SHA384:
                this.secret = padding(secret, 128, (byte) 0x00);
                this.opad = padding(this.opad, 128, (byte) 0x5C);
                this.ipad = padding(this.ipad, 128, (byte) 0x36);
                this.data = data;
                break;

            case HMAC_GOSTR3411:
                this.secret = padding(secret, 32, (byte) 0x00);
                this.opad = padding(this.opad, 32, (byte) 0x5C);
                this.ipad = padding(this.ipad, 32, (byte) 0x36);
                this.data = data;
                break;
        }

    }

    /**
     * Computes the hmac and returnes it.
     *
     * @return the computed hmac of the hmac instance
     *
     * @throws NoSuchAlgorithmException
     *
     */
    public byte[] compute() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest digest = null;
        //decides wich hash for the hmac should be used
        switch (this.macAlgorithm) {
            case HMAC_SHA1:
                digest = MessageDigest.getInstance("SHA-1");
                break;
            case HMAC_MD5:
                digest = MessageDigest.getInstance("MD5");
                break;
            case HMAC_SHA256:
                digest = MessageDigest.getInstance("SHA-256");
                break;
            case HMAC_SHA384:
                digest = MessageDigest.getInstance("SHA-384");
                break;
            case HMAC_GOSTR3411:
                digest = MessageDigest.getInstance("GOST3411");
                break;
            case HMAC_GOSTR3411_2012_256:
                digest = MessageDigest.getInstance("GOST3411-2012-256");
                break;
            default:
                throw new UnsupportedOperationException("Hash algorithm is not supported");
        }
        //hmac = hmac_<hash>(<hash>(secret XOR opad) || <hash>(secret XOR ipad || data))
        byte[] hash = digest.digest(ArrayConverter.concatenate(xorBytes(this.secret, this.ipad), this.data));
        this.hmac = digest.digest(ArrayConverter.concatenate(xorBytes(this.secret, this.opad), hash));
        return this.hmac;
    }

    /*
     * RFC 5246 5. HMAC and the Pseudorandom Function
     * p_hash is a data expansion function.
     * By taking a secret and a seed as input, a data expansion function produces an output of arbitrary length.
     * In here p_hash only computes one round of pseudo random bits (one use of the hmac)
     * To expand the secret, one can implement a PRF with p_hash as follows:
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) +
     *                        HMAC_hash(secret, A(3) + seed) + ...
     * where + indicates concatenation.
     * A() is defined as:
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i-1))
     * TLS's PRF is created by applying P_hash to the secret as:
     *   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
     *
     * The PseudoRandomFunction class takes use of the p_hash function.
     * */
    /**
     * p_hash is a data expansion function as described in RFC 5246 5. HMAC and the Pseudorandom Function
     *
     * @param secret the hmac key
     *
     * @param data the data that is going to be hashed
     *
     * @return returns a computation of the hmac instance
     *
     * @throws NoSuchAlgorithmException
     */
    public byte[] p_hash(byte[] secret, byte[] data) throws NoSuchAlgorithmException {
        init(secret, data);
        return compute();
    }

    /*
     * This function pads a specific byte to an byte array.
     * Has the byte array the same length as the length parameter of the function, the byte array will be returned without padding.
     * Is the byte array bigger than the length parameter the bytearray is hashed and returned.
     * */
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
            return hash(bytes);
        }
    }

    /*
     * XOR's two byte arrays and returns the result
     * */
    private byte[] xorBytes(byte[] a1, byte[] a2) {
        int length;
        if (a1.length > a2.length) {
            length = a2.length;
        } else {
            length = a1.length;
        }
        byte[] a3 = new byte[length];
        for (int i = 0; i < length; i++) {
            a3[i] = (byte) (a1[i] ^ a2[i]);
        }
        return a3;
    }

    /*
     * Hashes an array of bytes
     * */
    private byte[] hash(byte[] bytes) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest digest = null;
        switch (this.macAlgorithm) {
            case HMAC_SHA1:
                digest = MessageDigest.getInstance("SHA-1");
                break;
            case HMAC_MD5:
                digest = MessageDigest.getInstance("MD5");
                break;
            case HMAC_SHA256:
                digest = MessageDigest.getInstance("SHA-256");
                break;
            case HMAC_SHA384:
                digest = MessageDigest.getInstance("SHA-384");
                break;
            case HMAC_GOSTR3411:
                digest = MessageDigest.getInstance("GOST3411");
                break;
            case HMAC_GOSTR3411_2012_256:
                digest = MessageDigest.getInstance("GOST3411-2012-256");
                break;
            default:
                System.out.println("WARNING : NO HashAlgorithm");
        }
        return digest.digest(bytes);
    }
}
