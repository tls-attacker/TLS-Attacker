/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.crypto;

import de.rub.nds.tlsattacker.tls.exceptions.CryptoException;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Nurullah Erinola
 */
public class HKDFunction {

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

    public byte[] hkdfExtract(String macAlgorithm, byte[] salt, byte[] ikm) {
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

    public byte[] hkdfExpand(String macAlgorithm, byte[] prk, byte[] info, int outLen) {
        try {
            Mac mac = Mac.getInstance(macAlgorithm);
            SecretKeySpec keySpec = new SecretKeySpec(prk, macAlgorithm);
            mac.init(keySpec);
            byte[] out = new byte[0];
            byte[] ti = new byte[0];
            int i = 1;
            while (out.length < outLen) {
                mac.update(ti);
                // mac.update(info.getBytes());
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

    public byte[] hkdfLabelEncoder(byte[] hashValue, String labelIn, int outLen) {
        // Not Right
        String label = "TLS 1.3, " + labelIn;
        int labelLength = label.getBytes().length;
        int hashValueLength = hashValue.length;

        byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(outLen, 2),
                ArrayConverter.intToBytes(labelLength, 1), label.getBytes(),
                ArrayConverter.intToBytes(hashValueLength, 1), hashValue);
        return result;
    }

    public byte[] hkdfExpandLabel(String macAlgorithm, byte[] prk, byte[] hashValue, String labelIn, int outLen) {
        byte[] info = hkdfLabelEncoder(hashValue, labelIn, outLen);
        byte[] result = hkdfExpand(macAlgorithm, prk, info, outLen);
        return result;
    }

}
