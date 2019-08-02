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

public class EllipticCurveSECT163K1 extends EllipticCurveOverF2m {
    public EllipticCurveSECT163K1() {
        super(BigInteger.ONE, BigInteger.ONE, new BigInteger("800000000000000000000000000000000000000c9", 16),
                new BigInteger("02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8", 16), new BigInteger(
                        "0289070FB05D38FF58321F2E800536D538CCDAA3D9", 16), new BigInteger(
                        "04000000000000000000020108A2E0CC0D99F8A5EF", 16));
    }
}
