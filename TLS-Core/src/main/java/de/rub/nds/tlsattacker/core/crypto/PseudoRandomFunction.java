/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 * Pseudo random function computation for TLS 1.0 - 1.2 (for TLS 1.0, bouncy
 * castle TlsUtils are used)
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
     * @param prfAlgorithm
     *            PRFAlogirhtm
     * @param secret
     *            The Secret
     * @param label
     *            The Label
     * @param seed
     *            The Seed
     * @param size
     *            The size
     * @return the Prf output
     * @throws de.rub.nds.tlsattacker.core.exceptions.CryptoException
     */
    public static byte[] compute(PRFAlgorithm prfAlgorithm, byte[] secret, String label, byte[] seed, int size)
            throws CryptoException {

        switch (prfAlgorithm) {
            case TLS_PRF_SHA256:
            case TLS_PRF_SHA384:
            case TLS_PRF_GOSTR3411:
            case TLS_PRF_GOSTR3411_2012_256:
                return computeTls12(secret, label, seed, size, prfAlgorithm.getMacAlgorithm().getJavaName());
            case TLS_PRF_LEGACY:
                // prf legacy is the prf computation function for older protocol
                // versions, it works by default with sha1 and md5
                return TlsUtils.PRF_legacy(secret, label, seed, size);
            default:
                throw new UnsupportedOperationException("PRF computation for different"
                        + " protocol versions is not supported yet");
        }
    }

    /**
     * PRF computation for TLS 1.2
     *
     * @param prfAlgorithm
     *            PRFAlogirhtm
     * @param secret
     *            The Secret
     * @param label
     *            The Label
     * @param seed
     *            The Seed
     * @param size
     *            The size
     * @return the Prf output
     */
    private static byte[] computeTls12(byte[] secret, String label, byte[] seed, int size, String macAlgorithm)
            throws CryptoException {
        try {
            byte[] labelSeed = ArrayConverter.concatenate(label.getBytes(Charset.forName("ASCII")), seed);
            SecretKeySpec keySpec = null;

            if (secret == null || secret.length == 0) {
                try {
                    // empty key, but we still want to try to compute the
                    // SecretKeySpec
                    // Create an object using a fake key and then change that
                    // key back to a zero key with reflections
                    keySpec = new SecretKeySpec(new byte[] { 0, 0 }, macAlgorithm);
                    try {
                        Field field = keySpec.getClass().getDeclaredField("key");
                        field.setAccessible(true);
                        field.set(keySpec, new byte[0]);
                    } catch (NoSuchFieldException | IllegalAccessException | IllegalArgumentException
                            | SecurityException ex) {
                        throw new CryptoException("Could not access KeySpec with empty Key", ex);
                    }
                } catch (java.lang.IllegalArgumentException ex) {
                    throw new CryptoException("Could not tls12_prf output without Secret", ex);
                }
            } else {
                keySpec = new SecretKeySpec(secret, macAlgorithm);
            }

            Mac mac = Mac.getInstance(macAlgorithm);
            mac.init(keySpec);

            byte[] out = new byte[0];

            byte[] ai = labelSeed;
            byte[] buf;
            byte[] buf2;
            while (out.length < size) {
                mac.update(ai);
                buf = mac.doFinal();
                ai = buf;
                mac.update(ai);
                mac.update(labelSeed);
                buf2 = mac.doFinal();
                if (buf2.length == 0) {
                    throw new CryptoException("Could not Calc PRF output. Mac length is zero!");
                }
                out = ArrayConverter.concatenate(out, buf2);
            }
            return Arrays.copyOf(out, size);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    private PseudoRandomFunction() {

    }
}
