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

/**
 * Coprime pair generator which generates a lot of fractions and sieves out
 * those that qualify as "Trimmers".
 */
class SievingCoprimePairGenerator extends CoprimePairGenerator {

    private BigInteger uCandidate, tCandidate;
    private long maxQueryCount;

    public SievingCoprimePairGenerator(long maxQueryCount) {
        super();

        this.uCandidate = BigInteger.valueOf(1);
        this.tCandidate = BigInteger.valueOf(2);
        this.maxQueryCount = maxQueryCount;
    }

    @Override
    public BigInteger[] next() {
        ensureRange();

        while (uCandidate.gcd(tCandidate).compareTo(BigInteger.valueOf(1)) != 0) {
            uCandidate = uCandidate.add(BigInteger.ONE);
            ensureRange();
        }

        BigInteger[] pair = { uCandidate, tCandidate };
        uCandidate = uCandidate.add(BigInteger.ONE);
        numberOfQueries++;

        return pair;
    }

    /**
     * Makes sure that the pair's fraction is within the range given by Bardou
     * et al. 2012, by adjusting the values of u and t.
     */
    private void ensureRange() {
        float quotient = uCandidate.floatValue() / tCandidate.floatValue();

        if (quotient >= (3.0F / 2.0F)) {
            uCandidate = BigInteger.valueOf(1);
            tCandidate = tCandidate.add(BigInteger.ONE);
            quotient = uCandidate.floatValue() / tCandidate.floatValue();
        }
        while (quotient <= (2.0F / 3.0F)) {
            uCandidate = uCandidate.add(BigInteger.ONE);
            quotient = uCandidate.floatValue() / tCandidate.floatValue();
        }
    }

    @Override
    public boolean hasNext() {
        return numberOfQueries < maxQueryCount;
    }

}
