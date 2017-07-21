/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.keys;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CustomDHPrivateKey implements DHPrivateKey {

    private final BigInteger privateKey;
    private final BigInteger modulus;
    private final BigInteger generator;

    public CustomDHPrivateKey(BigInteger privateKey, BigInteger modulus, BigInteger generator) {
        this.privateKey = privateKey;
        this.modulus = modulus;
        this.generator = generator;
    }

    @Override
    public BigInteger getX() {
        return privateKey;
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
        throw new UnsupportedOperationException("CustomKey cannot be encoded");
    }

}
