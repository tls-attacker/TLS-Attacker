/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.mac;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

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
