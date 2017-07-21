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
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF functions computation for TLS 1.3
 * 
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class HKDFunction {

    public static final String KEY = "key";

    public static final String IV = "iv";

    public static final String FINISHED = "finished";

    public static final String DERIVED = "derived";

    public static final String BINDER_KEY_EXT = "ext binder";

    public static final String BINDER_KEY_RES = "res binder";

    public static final String CLIENT_EARLY_TRAFFIC_SECRET = "c e traffic";

    public static final String EARLY_EXPORTER_MASTER_SECRET = "e exp master";

    public static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET = "c hs traffic";

    public static final String SERVER_HANDSHAKE_TRAFFIC_SECRET = "s hs traffic";

    public static final String CLIENT_APPLICATION_TRAFFIC_SECRET = "c ap traffic";

    public static final String SERVER_APPLICATION_TRAFFIC_SECRET = "s ap traffic";

    public static final String EXPORTER_MASTER_SECRET = "exp master";

    public static final String RESUMPTION_MASTER_SECRET = "res master";

    public HKDFunction() {

    }

    /**
     * Computes HKDF-Extract output as defined in RFC 5869
     * 
     * @param hkdfAlgortihm
     * @param salt
     * @param ikm
     * @return
     */
    public static byte[] extract(HKDFAlgorithm hkdfAlgortihm, byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
            if (salt == null || salt.length == 0) {
                salt = new byte[mac.getMacLength()];
                Arrays.fill(salt, (byte) 0);
            }
            SecretKeySpec keySpec = new SecretKeySpec(salt, hkdfAlgortihm.getMacAlgorithm().getJavaName());
            mac.init(keySpec);
            mac.update(ikm);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * Computes HKDF-Expand output as defined in RFC 5869
     * 
     * @param hkdfAlgortihm
     * @param prk
     * @param info
     * @param outLen
     * @return
     */
    public static byte[] expand(HKDFAlgorithm hkdfAlgortihm, byte[] prk, byte[] info, int outLen) {
        try {
            Mac mac = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName());
            SecretKeySpec keySpec = new SecretKeySpec(prk, hkdfAlgortihm.getMacAlgorithm().getJavaName());
            mac.init(keySpec);
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            byte[] ti = new byte[0];
            int i = 1;
            while (stream.toByteArray().length < outLen) {
                mac.update(ti);
                mac.update(info);
                if (Integer.toHexString(i).length() % 2 != 0) {
                    mac.update(ArrayConverter.hexStringToByteArray("0" + Integer.toHexString(i)));
                } else {
                    mac.update(ArrayConverter.hexStringToByteArray(Integer.toHexString(i)));
                }
                ti = mac.doFinal();
                stream.write(ti);
                i++;
            }
            return Arrays.copyOfRange(stream.toByteArray(), 0, outLen);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    /**
     * Computes the HKDF-Label as defined in TLS 1.3
     */
    private static byte[] labelEncoder(byte[] hashValue, String labelIn, int outLen) {
        String label = "tls13 " + labelIn;
        int labelLength = label.getBytes().length;
        int hashValueLength = hashValue.length;
        byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(outLen, 2),
                ArrayConverter.intToBytes(labelLength, 1), label.getBytes(),
                ArrayConverter.intToBytes(hashValueLength, 1), hashValue);
        return result;
    }

    /**
     * Computes Derive-Secret output as defined in TLS 1.3
     * 
     * @param hkdfAlgortihm
     * @param hashAlgorithm
     * @param prk
     * @param labelIn
     * @param toHash
     * @return
     */
    public static byte[] deriveSecret(HKDFAlgorithm hkdfAlgortihm, String hashAlgorithm, byte[] prk, String labelIn,
            byte[] toHash) {
        try {
            MessageDigest hashFunction = MessageDigest.getInstance(hashAlgorithm);
            hashFunction.update(toHash);
            byte[] hashValue = hashFunction.digest();
            int outLen = Mac.getInstance(hkdfAlgortihm.getMacAlgorithm().getJavaName()).getMacLength();
            return expandLabel(hkdfAlgortihm, prk, labelIn, hashValue, outLen);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("Could not initialize HKDF", ex);
        }
    }

    /**
     * Computes HKDF-Expand-Label output as defined in TLS 1.3
     * 
     * @param hkdfAlgortihm
     * @param prk
     * @param labelIn
     * @param hashValue
     * @param outLen
     * @return
     */
    public static byte[] expandLabel(HKDFAlgorithm hkdfAlgortihm, byte[] prk, String labelIn, byte[] hashValue,
            int outLen) {
        byte[] info = labelEncoder(hashValue, labelIn, outLen);
        return expand(hkdfAlgortihm, prk, info, outLen);
    }

}
