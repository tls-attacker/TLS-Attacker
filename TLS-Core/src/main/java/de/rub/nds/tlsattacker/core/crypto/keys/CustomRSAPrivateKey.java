/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

public class CustomRSAPrivateKey extends CustomPrivateKey implements RSAPrivateKey {

    private final BigInteger modulus;
    private final BigInteger privateExponent;

    public CustomRSAPrivateKey(BigInteger modulus, BigInteger privateExponent) {
        this.modulus = modulus;
        this.privateExponent = privateExponent;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("CustomKey cannot be encoded");
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

}
