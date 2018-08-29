/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.mac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JavaMac implements WrappedMac {

    private final Mac mac;

    public JavaMac(String javaName, byte[] key) {
        try {
            mac = Mac.getInstance(javaName);
            mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new UnsupportedOperationException("Mac not supported: " + javaName, ex);
        }
    }

    @Override
    public byte[] calculateMac(byte[] data) {
        mac.update(data);
        return mac.doFinal();
    }

    @Override
    public int getMacLength() {
        return mac.getMacLength();
    }

}
