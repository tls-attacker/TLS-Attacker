/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import java.math.BigInteger;

/**
 * Coprime pair generator which generates a lot of fractions and sieves out those that qualify as "Trimmers".
 */
class SievingCoprimePairGenerator extends CoprimePairGenerator {

    private BigInteger tcandidate;
    private BigInteger ucandidate;
    private long maxQueryCount;

    public SievingCoprimePairGenerator(long maxQueryCount) {
        super();

        this.ucandidate = BigInteger.valueOf(1);
        this.tcandidate = BigInteger.valueOf(2);
        this.maxQueryCount = maxQueryCount;
    }

    @Override
    public BigInteger[] next() {
        ensureRange();

        while (ucandidate.gcd(tcandidate).compareTo(BigInteger.valueOf(1)) != 0) {
            ucandidate = ucandidate.add(BigInteger.ONE);
            ensureRange();
        }

        BigInteger[] pair = { ucandidate, tcandidate };
        ucandidate = ucandidate.add(BigInteger.ONE);
        numberOfQueries++;

        return pair;
    }

    /**
     * Makes sure that the pair's fraction is within the range given by Bardou et al. 2012, by adjusting the values of u
     * and t.
     */
    private void ensureRange() {
        float quotient = ucandidate.floatValue() / tcandidate.floatValue();

        if (quotient >= (3.0F / 2.0F)) {
            ucandidate = BigInteger.valueOf(1);
            tcandidate = tcandidate.add(BigInteger.ONE);
            quotient = ucandidate.floatValue() / tcandidate.floatValue();
        }
        while (quotient <= (2.0F / 3.0F)) {
            ucandidate = ucandidate.add(BigInteger.ONE);
            quotient = ucandidate.floatValue() / tcandidate.floatValue();
        }
    }

    @Override
    public boolean hasNext() {
        return numberOfQueries < maxQueryCount;
    }

}
