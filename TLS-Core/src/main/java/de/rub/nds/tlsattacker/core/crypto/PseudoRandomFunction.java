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

        byte[] output_md5;
        byte[] output_sha;
        byte[] pseudoRandomBitStream = new byte[0];
        byte[] salt_byte = { 0x41 };
        byte[] salt = { 0x41 };

        /*
         * To generate the key material, compute pseudoRandomBitStream = MD5(master_secret + SHA(`A' + master_secret +
         * ServerHello.random + ClientHello.random)) + MD5(master_secret + SHA(`BB' + master_secret + ServerHello.random
         * + ClientHello.random)) + MD5(master_secret + SHA(`CCC' + master_secret + ServerHello.random +
         * ClientHello.random)) + [...]; until enough output has been generated.
         */
        while (pseudoRandomBitStream.length < size) {
            output_sha = sha.hash(ArrayConverter.concatenate(salt, master_secret, server_random, client_random));
            output_md5 = md5.hash(ArrayConverter.concatenate(master_secret, output_sha));

            pseudoRandomBitStream = ArrayConverter.concatenate(pseudoRandomBitStream, output_md5);

            /*
             * Adds another byte to the salt and increments the howl salt array by one bit afterwards as in the command
             * above described
             */
            salt = ArrayConverter.concatenate(salt, salt_byte);
            salt_byte[0] += 0x01;
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
            HMAC hmac_md5 = new HMAC(MacAlgorithm.HMAC_MD5);
            HMAC hmac_sha1 = new HMAC(MacAlgorithm.HMAC_SHA1);

            int length;
            int s_half = (secret.length + 1) / 2;
            byte[] s1 = new byte[s_half];
            byte[] s2 = new byte[s_half];
            System.arraycopy(secret, 0, s1, 0, s_half);
            System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

            byte[] extendedSecret_md5 = new byte[0];
            byte[] extendedSecret_sha1 = new byte[0];

            byte[] ai = labelSeed;

            /*
             * Expands the first half of the secret with the p_hash function, which uses md5
             */
            while (extendedSecret_md5.length < size) {
                ai = hmac_md5.p_hash(s1, ai);
                extendedSecret_md5 = ArrayConverter.concatenate(extendedSecret_md5,
                    hmac_md5.p_hash(s1, ArrayConverter.concatenate(ai, labelSeed)));
            }

            ai = labelSeed;

            /*
             * Expands the second half of the secret with the p_hash function, which uses sha1
             */
            while (extendedSecret_sha1.length < size) {
                ai = hmac_sha1.p_hash(s2, ai);
                extendedSecret_sha1 = ArrayConverter.concatenate(extendedSecret_sha1,
                    hmac_sha1.p_hash(s2, ArrayConverter.concatenate(ai, labelSeed)));
            }

            if (extendedSecret_md5.length > extendedSecret_sha1.length) {
                length = extendedSecret_sha1.length;
            } else {
                length = extendedSecret_md5.length;
            }

            byte[] pseudoRandomBitStream = new byte[length];

            /*
             * Produces the key block (pseudo random bit stream) by xoring the extended secrets
             */
            for (int i = 0; i < length; i++) {
                pseudoRandomBitStream[i] = (byte) (extendedSecret_md5[i] ^ extendedSecret_sha1[i]);
            }

            return Arrays.copyOf(pseudoRandomBitStream, size);
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

            byte[] pseudoRandomBitStream = new byte[0];
            byte[] ai = labelSeed;

            /*
             * Expands the secret to produce the key block (pseudo random bit stream)
             */
            while (pseudoRandomBitStream.length < size) {
                ai = hmac.p_hash(secret, ai);
                pseudoRandomBitStream = ArrayConverter.concatenate(pseudoRandomBitStream,
                    hmac.p_hash(secret, ArrayConverter.concatenate(ai, labelSeed)));
            }

            return Arrays.copyOf(pseudoRandomBitStream, size);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    private PseudoRandomFunction() {
    }
}