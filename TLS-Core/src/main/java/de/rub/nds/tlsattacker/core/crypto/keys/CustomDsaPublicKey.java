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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;

/**
 *
 * @author robert
 */
public class CustomDsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    private final BigInteger publicKey;

    public CustomDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger publicKey) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.publicKey = publicKey;
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

    @Override
    public BigInteger getY() {
        return publicKey;
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(p, q, g);
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
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
