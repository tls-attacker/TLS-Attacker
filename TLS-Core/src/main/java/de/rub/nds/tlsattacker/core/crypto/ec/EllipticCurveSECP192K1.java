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

public class EllipticCurveSECP192K1 extends EllipticCurveOverFp {
    public EllipticCurveSECP192K1() {
        super(BigInteger.ZERO, new BigInteger("3"), new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
                16), new BigInteger("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16), new BigInteger(
                "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16), new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16));
    }
}
