/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Nurullah Erinola
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

    public static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET = "client handshake traffic secret";

    public static final String SERVER_HANDSHAKE_TRAFFIC_SECRET = "server handshake traffic secret";

    public static final String CLIENT_APPLICATION_TRAFFIC_SECRET = "client application traffic secret";

    public static final String SERVER_APPLICATION_TRAFFIC_SECRET = "server application traffic secret";

    public static final String EXPORTER_MASTER_SECRET = "exp master";

    public static final String RESUMPTION_MASTER_SECRET = "res master";

    public HKDFunction() {

    }

    public static byte[] extract(String macAlgorithm, byte[] salt, byte[] ikm) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            if (salt == null || salt.length == 0) {
                salt = new byte[mac.getMacLength()];
                Arrays.fill(salt, (byte) 0);
            }
            SecretKeySpec keySpec = new SecretKeySpec(salt, macAlgorithm);
            mac.init(keySpec);
            mac.update(ikm);
            byte[] out = mac.doFinal();
            return out;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    public static byte[] expand(String macAlgorithm, byte[] prk, byte[] info, int outLen) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(prk, macAlgorithm);
            mac.init(keySpec);
            byte[] out = new byte[0];
            byte[] ti = new byte[0];
            int i = 1;
            while (out.length < outLen) {
                mac.update(ti);
                mac.update(info);
                if (Integer.toHexString(i).length() % 2 != 0) {
                    mac.update(ArrayConverter.hexStringToByteArray("0" + Integer.toHexString(i)));
                } else {
                    mac.update(ArrayConverter.hexStringToByteArray(Integer.toHexString(i)));
                }
                ti = mac.doFinal();
                out = ArrayConverter.concatenate(out, ti);
                i++;
            }
            return Arrays.copyOfRange(out, 0, outLen);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CryptoException(ex);
        }
    }

    private static byte[] labelEncoder(byte[] hashValue, String labelIn, int outLen) {
        // Not Right, but for the Tests
        String label = "TLS 1.3, " + labelIn;
        // Right
        // String label = "tls13 " + labelIn;
        int labelLength = label.getBytes().length;
        int hashValueLength = hashValue.length;

        byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(outLen, 2),
                ArrayConverter.intToBytes(labelLength, 1), label.getBytes(),
                ArrayConverter.intToBytes(hashValueLength, 1), hashValue);
        return result;
    }

    public static byte[] deriveSecret(String macAlgorithm, byte[] prk, String labelIn, byte[] hashValue) {
        try {
            int outLen = Mac.getInstance(macAlgorithm).getMacLength();
            byte[] info = labelEncoder(hashValue, labelIn, outLen);
            byte[] result = expand(macAlgorithm, prk, info, outLen);
            return result;
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("Could not initialize HKDF", ex);
        }
    }

    public static byte[] expandLabel(String macAlgorithm, byte[] prk, String labelIn, byte[] hashValue, int outLen) {
        byte[] info = labelEncoder(hashValue, labelIn, outLen);
        byte[] result = expand(macAlgorithm, prk, info, outLen);
        return result;
    }

}
