/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl.drown;

import java.math.BigInteger;

class SimpleCoprimePairGenerator extends CoprimePairGenerator {

    private long nextU = 1;
    private long maxQueries;

    public SimpleCoprimePairGenerator(long maxQueries) {
        super();
        this.maxQueries = maxQueries;
    }

    @Override
    public BigInteger[] next() {
        // TODO: Intuitively, neighboring number should always be coprime, but
        // is that really the case?
        long t = nextU + 1;
        BigInteger[] pair = { BigInteger.valueOf(nextU), BigInteger.valueOf(t) };

        numberOfQueries++;
        nextU += 2;

        return pair;
    }

    @Override
    public boolean hasNext() {
        return numberOfQueries < maxQueries;
    }

}
