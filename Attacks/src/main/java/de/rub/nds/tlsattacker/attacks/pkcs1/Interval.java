/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.pkcs1;

import java.math.BigInteger;

/**
 * M interval as mentioned in the Bleichenbacher paper.
 *
 * @version 0.1 May 24, 2012
 */
public class Interval {

    /**
     *
     */
    public BigInteger lower;

    /**
     *
     */
    public BigInteger upper;

    /**
     *
     * @param a
     * @param b
     */
    public Interval(BigInteger a, BigInteger b) {
        this.lower = a;
        this.upper = b;
        if (a.compareTo(b) > 0) {
            throw new RuntimeException("something went wrong, a cannot be greater than b");
        }
    }
}
