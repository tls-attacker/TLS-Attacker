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

public class EllipticCurveSECT283R1 extends EllipticCurveOverF2m {
    public EllipticCurveSECT283R1() {
        super(BigInteger.ONE, new BigInteger(
                "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5", 16), new BigInteger(
                "800000000000000000000000000000000000000000000000000000000000000000010a1", 16), new BigInteger(
                "05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053", 16), new BigInteger(
                "03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4", 16), new BigInteger(
                "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307", 16));
    }
}
