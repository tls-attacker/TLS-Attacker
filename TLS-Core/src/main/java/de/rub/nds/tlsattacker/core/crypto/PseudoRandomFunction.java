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
import org.bouncycastle.crypto.tls.TlsUtils;


/**
 * Pseudo random function computation for TLS 1.0 - 1.2 (for TLS 1.0, bouncy castle TlsUtils are used)
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
     * Computes PRF output of the provided size using the given mac algorithm
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
    public static byte[] compute(PRFAlgorithm prfAlgorithm, byte[] secret, String label, byte[] seed, int size) throws CryptoException {
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
            //return TlsUtils.PRF_legacy(secret, label, seed, size);
            default:
                throw new UnsupportedOperationException(
                        "PRF computation for different" + " protocol versions is not supported yet");
        }
    }

    private static byte[] computeTls10(byte[] secret, String label, byte[] seed, int size) throws CryptoException {
        try {
            byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(Charset.forName("ASCII")), seed);
            HMAC hmac_md5 = new HMAC(MacAlgorithm.HMAC_MD5);
            HMAC hamc_sha1 = new HMAC(MacAlgorithm.HMAC_SHA1);

            int length;
            int s_half = (secret.length + 1) / 2;
            byte[] s1 = new byte[s_half];
            byte[] s2 = new byte[s_half];
            System.arraycopy(secret, 0, s1, 0, s_half);
            System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

            byte[] extendedSecret_md5 = new byte[0];
            byte[] extendedSecret_sha1 = new byte[0];

            byte[] ai = labelSeed;

            while (extendedSecret_md5.length < size) {
                ai = hmac_md5.p_hash(s1, ai);
                extendedSecret_md5 = ArrayConverter.concatenate(extendedSecret_md5,
                        hmac_md5.p_hash(s1, ArrayConverter.concatenate(ai, labelSeed)));
            }

            ai = labelSeed;
            while (extendedSecret_sha1.length < size) {
                ai = hamc_sha1.p_hash(s2, ai);
                extendedSecret_sha1 = ArrayConverter.concatenate(extendedSecret_sha1,
                        hamc_sha1.p_hash(s2, ArrayConverter.concatenate(ai, labelSeed)));
            }

            if (extendedSecret_md5.length > extendedSecret_sha1.length) {
                length = extendedSecret_sha1.length;
            } else {
                length = extendedSecret_md5.length;
            }

            byte[] pseudoRandomBitStream = new byte[length];

            for (int i = 0; i < length; i++) {
                pseudoRandomBitStream[i] = (byte) (extendedSecret_md5[i] ^ extendedSecret_sha1[i]);
            }

            return Arrays.copyOf(pseudoRandomBitStream, size);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * PRF computation for TLS 1.2
     *s
     * @param  macAlgorithm
     *                      PRFAlgorithm
     * @param  secret
     *                      The Secret
     * @param  label
     *                      The Label
     * @param  seed
     *                      The Seed
     * @param  size
     *                      The size
     * @return              the Prf output
     */
    private static byte[] computeTls12(byte[] secret, String label, byte[] seed, int size, MacAlgorithm macAlgorithm) throws CryptoException {
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