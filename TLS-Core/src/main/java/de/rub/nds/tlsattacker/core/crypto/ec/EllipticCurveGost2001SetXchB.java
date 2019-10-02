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

public class EllipticCurveGost2001SetXchB extends EllipticCurveOverF2m {

    public EllipticCurveGost2001SetXchB() {
        super(new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"),
                new BigInteger("28091019353058090096996979000309560759124368558014865957655842872397301267595"),
                new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823193"),
                new BigInteger("1"), new BigInteger(
                        "28792665814854611296992347458380284135028636778229113005756334730996303888124"),
                new BigInteger("57896044618658097711785492504343953927102133160255826820068844496087732066703"));
    }

}
