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

public class EllipticCurveSECT193R2 extends EllipticCurveOverF2m {
    public EllipticCurveSECT193R2() {
        super(new BigInteger("0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B", 16), new BigInteger(
                "00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE", 16), new BigInteger(
                "2000000000000000000000000000000000000000000008001", 16), new BigInteger(
                "00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F", 16), new BigInteger(
                "01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C", 16), new BigInteger(
                "010000000000000000000000015AAB561B005413CCD4EE99D5", 16));
    }
}
