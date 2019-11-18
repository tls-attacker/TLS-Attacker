/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;

public class EllipticCurveGost2001SetXchA extends EllipticCurveOverF2m {

    public EllipticCurveGost2001SetXchA() {
        super(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"),
                new BigInteger("166"), new BigInteger(
                        "115792089237316195423570985008687907853269984665640564039457584007913129639319"),
                new BigInteger("1"), new BigInteger(
                        "64033881142927202683649881450433473985931760268884941288852745803908878638612"),
                new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323"));
    }

}
