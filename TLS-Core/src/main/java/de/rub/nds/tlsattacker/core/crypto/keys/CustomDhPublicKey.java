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
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class CustomDhPublicKey extends CustomPublicKey implements DHPublicKey {

    private final BigInteger modulus;
    
    private final BigInteger generator;
    
    private final BigInteger publicKey;

    public CustomDhPublicKey(BigInteger modulus, BigInteger generator, BigInteger publicKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.publicKey = publicKey;
    }
    
    @Override
    public void adjustInContext(TlsContext context, ConnectionEndType ownerOfKey) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public BigInteger getY() {
        return publicKey;
    }

    @Override
    public DHParameterSpec getParams() {
        return new DHParameterSpec(modulus, generator);
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
