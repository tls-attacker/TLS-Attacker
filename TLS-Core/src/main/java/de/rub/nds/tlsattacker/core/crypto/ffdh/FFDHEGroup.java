/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.ffdh;

import java.math.BigInteger;

public abstract class FFDHEGroup {

    private final BigInteger g;
    private final BigInteger p;

    public FFDHEGroup(BigInteger g, BigInteger p) {
        this.g = g;
        this.p = p;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }
}
