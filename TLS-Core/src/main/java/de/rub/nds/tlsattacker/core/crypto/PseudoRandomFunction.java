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
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Pseudo random function computation for SSL3, TLS 1.0 - 1.2
 */
public class PseudoRandomFunction {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * master secret label
     */
    public static final String MASTER_SECRET_LABEL = "master secret";

    /**
     * client finished label
     */
    public static final String CLIENT_FINISHED_LABEL = "client finished";

    /**
     * server finished label
     */
    public static final String SERVER_FINISHED_LABEL = "server finished";

    /**
     * key expansion label
     */
    public static final String KEY_EXPANSION_LABEL = "key expansion";

    /**
     * extended master secret
     */
    public static final String EXTENDED_MASTER_SECRET_LABEL = "extended master secret";

    public static final String CLIENT_WRITE_KEY_LABEL = "client write key";

    public static final String SERVER_WRITE_KEY_LABEL = "server write key";

    public static final String IV_BLOCK_LABEL = "IV block";

    /**
     * Computes the PRF output for SSL3 of the provided size
     *
     * @param  master_secret
     *                                  the master secret
     *
     * @param  client_random
     *                                  the client random
     *
     * @param  server_random
     *                                  the server random
     *
     * @param  size
     *                                  the size of the key block
     *
     * @return                          the key block as pseudo random bit stream
     * @throws NoSuchAlgorithmException
     */
    public static byte[] computeSSL3(byte[] master_secret, byte[] client_random, byte[] server_random, int size)
        throws NoSuchAlgorithmException {
        HMAC md5 = new HMAC(MacAlgorithm.HMAC_MD5);
        HMAC sha = new HMAC(MacAlgorithm.HMAC_SHA1);

        byte[] outputMd5;
        byte[] outputSha;
        byte[] pseudoRandomBitStream = new byte[0];
        byte[] salt = { 0x41 };
        byte[] saltByte = { 0x41 };

        /*
         * To generate the key material, compute pseudoRandomBitStream = MD5(master_secret + SHA(`A' + master_secret +
         * ServerHello.random + ClientHello.random)) + MD5(master_secret + SHA(`BB' + master_secret + ServerHello.random
         * + ClientHello.random)) + MD5(master_secret + SHA(`CCC' + master_secret + ServerHello.random +
         * ClientHello.random)) + [...]; until enough output has been generated.
         */
        while (pseudoRandomBitStream.length < size) {
            outputSha =
                sha.getDigest().digest(ArrayConverter.concatenate(salt, master_secret, server_random, client_random));
            outputMd5 = md5.getDigest().digest(ArrayConverter.concatenate(master_secret, outputSha));

            pseudoRandomBitStream = ArrayConverter.concatenate(pseudoRandomBitStream, outputMd5);

            /*
             * Adds another byte to the salt and increments the whole salt array by one bit afterwards as in the command
             * above described
             */
            salt = ArrayConverter.concatenate(salt, saltByte);
            saltByte[0] += 0x01;
            for (int j = 0; j < salt.length; j++) {
                salt[j] += 0x01;
            }
        }
        return Arrays.copyOf(pseudoRandomBitStream, size);
    }

    /**
     * Computes the PRF output for TLS1.0 - TLS1.2 of the provided size using the given mac algorithm
     *
     * @param  prfAlgorithm
     *                                                                PRFAlgorithm
     * @param  secret
     *                                                                The Secret
     * @param  label
     *                                                                The Label
     * @param  seed
     *                                                                The Seed
     * @param  size
     *                                                                The size
     * @return                                                        the Prf output
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    public static byte[] compute(PRFAlgorithm prfAlgorithm, byte[] secret, String label, byte[] seed, int size)
        throws CryptoException {
        if (prfAlgorithm == null) {
            LOGGER.warn("Trying to compute PRF without specified PRF algorithm. Using TLS 1.0/TLS 1.1 as default.");
            prfAlgorithm = PRFAlgorithm.TLS_PRF_LEGACY;
        }
        switch (prfAlgorithm) {
            case TLS_PRF_SHA256:
                return computeTls12(secret, label, seed, size, MacAlgorithm.HMAC_SHA256);
            case TLS_PRF_SHA384:
                return computeTls12(secret, label, seed, size, MacAlgorithm.HMAC_SHA384);
            case TLS_PRF_GOSTR3411:
                return computeTls12(secret, label, seed, size, MacAlgorithm.HMAC_GOSTR3411);
            case TLS_PRF_GOSTR3411_2012_256:
                return computeTls12(secret, label, seed, size, MacAlgorithm.HMAC_GOSTR3411_2012_256);
            case TLS_PRF_LEGACY:
                // prf legacy is the prf computation function for older protocol
                // versions, it works by default with sha1 and md5
                return computeTls10(secret, label, seed, size);
            default:
                throw new UnsupportedOperationException(
                    "PRF computation for different" + " protocol versions is not supported yet");
        }
    }

    private static byte[] computeTls10(byte[] secret, String label, byte[] seed, int size) throws CryptoException {
        try {
            byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(Charset.forName("ASCII")), seed);
            byte[] pseudoRandomBitStream = new byte[size];

            HMAC hmacMd5 = new HMAC(MacAlgorithm.HMAC_MD5);
            HMAC hmacSha1 = new HMAC(MacAlgorithm.HMAC_SHA1);

            /*
             * Divides the secret into two halves, s1 and s2
             */
            int offset = (secret.length + 1) / 2;
            byte[] s1 = new byte[offset];
            byte[] s2 = new byte[offset];
            System.arraycopy(secret, 0, s1, 0, offset);
            System.arraycopy(secret, secret.length - offset, s2, 0, offset);

            hmacMd5.init(s1);
            hmacSha1.init(s2);

            /*
             * Expands the first half of the secret with the p_hash function, which uses md5
             */
            byte[] extendedSecretMd5 = p_hash(hmacMd5, labelSeed, size);

            /*
             * Expands the second half of the secret with the p_hash function, which uses sha1
             */
            byte[] extendedSecretSha1 = p_hash(hmacSha1, labelSeed, size);

            /*
             * Produces the pseudo random bit stream by xoring the extended secrets
             */
            for (int i = 0; i < size; i++) {
                pseudoRandomBitStream[i] = (byte) (extendedSecretMd5[i] ^ extendedSecretSha1[i]);
            }

            return pseudoRandomBitStream;
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * PRF computation for TLS 1.2 s
     * 
     * @param  macAlgorithm
     *                      PRFAlgorithm
     * @param  secret
     *                      The Secret
     * @param  label
     *                      The Label
     * @param  seed
     *                      The Seed
     * @param  size
     *                      The size of the pseudo random bit stream
     * @return              the key block material
     */
    private static byte[] computeTls12(byte[] secret, String label, byte[] seed, int size, MacAlgorithm macAlgorithm)
        throws CryptoException {
        try {
            byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(Charset.forName("ASCII")), seed);
            HMAC hmac = new HMAC(macAlgorithm);

            if (secret == null || secret.length == 0) {
                // empty key, but we still want to try to compute the
                // SecretKeySpec
                hmac.setSecret(new byte[0]);
            }

            hmac.init(secret);

            /*
             * Expands the secret to produce the pseudo random bit stream
             */
            byte[] pseudoRandomBitStream = p_hash(hmac, labelSeed, size);

            return pseudoRandomBitStream;
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    /*
     * RFC 5246 5. HMAC and the Pseudorandom Function p_hash is a data expansion function. By taking a secret and a seed
     * as input, a data expansion function produces an output of arbitrary length. In here, p_hash only computes one
     * round of pseudo random bits (one use of the hmac) To expand the secret, one can implement a PRF with p_hash as
     * follows: P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) +
     * HMAC_hash(secret, A(3) + seed) + ... where + indicates concatenation. A() is defined as: A(0) = seed A(i) =
     * HMAC_hash(secret, A(i-1)) TLS's PRF is created by applying P_hash to the secret as: PRF(secret, label, seed) =
     * P_<hash>(secret, label + seed)
     *
     * The PseudoRandomFunction class takes use of the p_hash function.
     */

    /**
     * p_hash is a data expansion function as described in RFC 5246 5. HMAC and the Pseudorandom Function
     * 
     * @param  hmac
     * @param  data
     * @param  size
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static byte[] p_hash(HMAC hmac, byte[] data, int size) throws NoSuchAlgorithmException {
        byte[] extendedSecret = new byte[0];

        /*
         * hmacIteration will be used as an input for the next hmac, which will generate the actual bytes for the
         * extendedSecret
         */
        byte[] hmacIteration = data;

        /*
         * Expands the secret
         */
        while (extendedSecret.length < size) {
            hmacIteration = hmac.doFinal(hmacIteration);
            extendedSecret = ArrayConverter.concatenate(extendedSecret,
                hmac.doFinal(ArrayConverter.concatenate(hmacIteration, data)));
        }
        return Arrays.copyOf(extendedSecret, size);
    }

    private PseudoRandomFunction() {
    }
}