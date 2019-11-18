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

public class EllipticCurveSECP160R2 extends EllipticCurveOverFp {
    public EllipticCurveSECP160R2() {
        super(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70", 16), new BigInteger(
                "B4E134D3FB59EB8BAB57274904664D5AF50388BA", 16), new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16), new BigInteger(
                "52DCB034293A117E1F4FF11B30F7199D3144CE6D", 16), new BigInteger(
                "FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", 16), new BigInteger(
                "0100000000000000000000351EE786A818F3A1A16B", 16));
    }
}
