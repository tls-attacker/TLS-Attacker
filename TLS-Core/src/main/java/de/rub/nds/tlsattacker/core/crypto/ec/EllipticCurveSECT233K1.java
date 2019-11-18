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

public class EllipticCurveSECT233K1 extends EllipticCurveOverF2m {
    public EllipticCurveSECT233K1() {
        super(BigInteger.ZERO, BigInteger.ONE, new BigInteger(
                "20000000000000000000000000000000000000004000000000000000001", 16), new BigInteger(
                "017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126", 16), new BigInteger(
                "01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3", 16), new BigInteger(
                "8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF", 16));
    }
}
