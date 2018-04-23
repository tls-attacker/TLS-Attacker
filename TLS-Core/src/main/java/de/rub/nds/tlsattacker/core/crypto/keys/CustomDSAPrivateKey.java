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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;

public class CustomDSAPrivateKey implements DSAPrivateKey {

    private final BigInteger privateKey;

    private final BigInteger primeP;
    private final BigInteger primeQ;
    private final BigInteger generator;

    public CustomDSAPrivateKey(BigInteger privateKey, BigInteger primeP, BigInteger primeQ, BigInteger generator) {
        this.privateKey = privateKey;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.generator = generator;
    }

    @Override
    public BigInteger getX() {
        return privateKey;
    }

    @Override
    public DSAParams getParams() {
        return new DSAParameterSpec(primeP, primeQ, generator);
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "DSA";
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
