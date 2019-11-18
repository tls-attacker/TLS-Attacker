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

public class EllipticCurveSECP224R1 extends EllipticCurveOverFp {
    public EllipticCurveSECP224R1() {
        super(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16), new BigInteger(
                "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16), new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16), new BigInteger(
                "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16), new BigInteger(
                "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16), new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16));
    }
}
