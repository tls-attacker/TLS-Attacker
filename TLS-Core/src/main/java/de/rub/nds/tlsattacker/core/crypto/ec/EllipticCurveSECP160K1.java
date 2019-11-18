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

public class EllipticCurveSECP160K1 extends EllipticCurveOverFp {
    public EllipticCurveSECP160K1() {
        super(BigInteger.ZERO, new BigInteger("7"), new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16),
                new BigInteger("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", 16), new BigInteger(
                        "938CF935318FDCED6BC28286531733C3F03C4FEE", 16), new BigInteger(
                        "0100000000000000000001B8FA16DFAB9ACA16B6B3", 16));
    }
}
