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
import java.security.interfaces.RSAPrivateKey;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CustomDSAPrivateKey implements RSAPrivateKey {

    private final BigInteger privateExponent;

    private final BigInteger modulus;

    public CustomDSAPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        this.privateExponent = privateExponent;
        this.modulus = modulus;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
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
        throw new UnsupportedOperationException("CustomKey cannot be encoded");
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

}
