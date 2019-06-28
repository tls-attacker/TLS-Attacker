/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.tlsattacker.core.constants.GOSTCurve;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;

public class CurveFactory {

    /**
     * Returns a named elliptic curve.
     *
     * @param name
     *            The name of the curve, that should be returned.
     */
    public static EllipticCurve getCurve(NamedGroup name) {
        switch (name) {
            case BRAINPOOLP256R1:
                return new EllipticCurveBrainpoolP256R1();
            case BRAINPOOLP384R1:
                return new EllipticCurveBrainpoolP384R1();
            case BRAINPOOLP512R1:
                return new EllipticCurveBrainpoolP512R1();
            case SECP160K1:
                return new EllipticCurveSECP160K1();
            case SECP160R1:
                return new EllipticCurveSECP160R1();
            case SECP160R2:
                return new EllipticCurveSECP160R2();
            case SECP192K1:
                return new EllipticCurveSECP192K1();
            case SECP192R1:
                return new EllipticCurveSECP192R1();
            case SECP224K1:
                return new EllipticCurveSECP224K1();
            case SECP224R1:
                return new EllipticCurveSECP224R1();
            case SECP256K1:
                return new EllipticCurveSECP256K1();
            case SECP256R1:
                return new EllipticCurveSECP256R1();
            case SECP384R1:
                return new EllipticCurveSECP384R1();
            case SECP521R1:
                return new EllipticCurveSECP521R1();
            case SECT163K1:
                return new EllipticCurveSECT163K1();
            case SECT163R1:
                return new EllipticCurveSECT163R1();
            case SECT163R2:
                return new EllipticCurveSECT163R2();
            case SECT193R1:
                return new EllipticCurveSECT193R1();
            case SECT193R2:
                return new EllipticCurveSECT193R2();
            case SECT233K1:
                return new EllipticCurveSECT233K1();
            case SECT233R1:
                return new EllipticCurveSECT233R1();
            case SECT239K1:
                return new EllipticCurveSECT239K1();
            case SECT283K1:
                return new EllipticCurveSECT283K1();
            case SECT283R1:
                return new EllipticCurveSECT283R1();
            case SECT409K1:
                return new EllipticCurveSECT409K1();
            case SECT409R1:
                return new EllipticCurveSECT409R1();
            case SECT571K1:
                return new EllipticCurveSECT571K1();
            case SECT571R1:
                return new EllipticCurveSECT571R1();
            default:
                throw new UnsupportedOperationException("The provided curve '" + name + "' is not supported.");

        }
    }

    /**
     * Returns a named gost curve.
     *
     * @param curve
     *            The name of the curve, that should be returned.
     * @return
     */
    public static EllipticCurve getCurve(GOSTCurve curve) {
        switch (curve) {
            case GostR3410_2001_CryptoPro_A:
                return new EllipticCurveGost2001SetA();
            case GostR3410_2001_CryptoPro_B:
                return new EllipticCurveGost2001SetB();
            case GostR3410_2001_CryptoPro_C:
                return new EllipticCurveGost2001SetC();
            case GostR3410_2001_CryptoPro_XchA:
                return new EllipticCurveGost2001SetXchA();
            case GostR3410_2001_CryptoPro_XchB:
                return new EllipticCurveGost2001SetXchB();
            case Tc26_Gost_3410_12_256_paramSetA:
                return new EllipticCurveGost2012SetA256();
            case Tc26_Gost_3410_12_512_paramSetA:
                return new EllipticCurveGost2012SetA512();
            case Tc26_Gost_3410_12_512_paramSetB:
                return new EllipticCurveGost2012SetB512();
            case Tc26_Gost_3410_12_512_paramSetC:
                return new EllipticCurveGost2012SetC512();
            default:
                throw new UnsupportedOperationException("The provided curve '" + curve + "' is not supported.");

        }
    }

    private CurveFactory() {
    }

}
