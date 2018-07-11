/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec_;

public class CurveFactory {

    /**
     * Returns a named elliptic curve.
     * 
     * @param name
     *            The name of the curve, that should be returned.
     */
    public static EllipticCurve getCurve(String name) {
        name = name.toLowerCase();

        if (name.equals("secp160k1"))
            return new EllipticCurveSECP160K1();
        if (name.equals("secp160r1"))
            return new EllipticCurveSECP160R1();
        if (name.equals("secp160r2"))
            return new EllipticCurveSECP160R2();
        if (name.equals("secp192k1"))
            return new EllipticCurveSECP192K1();
        if (name.equals("secp192r1"))
            return new EllipticCurveSECP192R1();
        if (name.equals("secp224k1"))
            return new EllipticCurveSECP224K1();
        if (name.equals("secp224r1"))
            return new EllipticCurveSECP224R1();
        if (name.equals("secp256k1"))
            return new EllipticCurveSECP256K1();
        if (name.equals("secp256r1"))
            return new EllipticCurveSECP256R1();
        if (name.equals("secp384r1"))
            return new EllipticCurveSECP384R1();
        if (name.equals("secp521r1"))
            return new EllipticCurveSECP521R1();
        if (name.equals("brainpoolp256r1"))
            return new EllipticCurveBrainpoolP256R1();
        if (name.equals("brainpoolp384r1"))
            return new EllipticCurveBrainpoolP384R1();
        if (name.equals("brainpoolp512r1"))
            return new EllipticCurveBrainpoolP512R1();
        if (name.equals("sect163k1"))
            return new EllipticCurveSECT163K1();
        if (name.equals("sect163r1"))
            return new EllipticCurveSECT163R1();
        if (name.equals("sect163r2"))
            return new EllipticCurveSECT163R2();
        if (name.equals("sect193r1"))
            return new EllipticCurveSECT193R1();
        if (name.equals("sect193r2"))
            return new EllipticCurveSECT193R2();
        if (name.equals("sect233k1"))
            return new EllipticCurveSECT233K1();
        if (name.equals("sect233r1"))
            return new EllipticCurveSECT233R1();
        if (name.equals("sect239k1"))
            return new EllipticCurveSECT239K1();
        if (name.equals("sect283k1"))
            return new EllipticCurveSECT283K1();
        if (name.equals("sect283r1"))
            return new EllipticCurveSECT283R1();
        if (name.equals("sect409k1"))
            return new EllipticCurveSECT409K1();
        if (name.equals("sect409r1"))
            return new EllipticCurveSECT409R1();
        if (name.equals("sect571k1"))
            return new EllipticCurveSECT571K1();
        if (name.equals("sect571r1"))
            return new EllipticCurveSECT571R1();

        throw new UnsupportedOperationException("The provided curve '" + name + "' is not supported.");
    }

}
