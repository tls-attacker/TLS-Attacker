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


public class CurveFactory {

    public static Curve getNamedCurve(String namedCurve) {
        BigInteger p, a, b;
        int bits;
        String namedCurveLow = namedCurve.toLowerCase();

        switch (namedCurveLow) {
            case "secp192r1":
                p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
                a = new BigInteger("6277101735386680763835789423207666416083908700390324961276");
                b = new BigInteger("2455155546008943817740293915197451784769108058161191238065");
                bits = 192;
                break;

            case "secp256r1":
                p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
                a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
                b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
                bits = 256;
                break;
            default:
                throw new UnsupportedOperationException("The provided curve " + namedCurve + " not supported yet");
        }
        return new Curve(namedCurveLow, p, a, b, bits);
    }

    private CurveFactory() {

    }

}
