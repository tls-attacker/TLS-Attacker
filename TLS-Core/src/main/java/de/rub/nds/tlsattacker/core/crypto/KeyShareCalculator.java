/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.GroupFactory;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] createPublicKey(NamedGroup group, BigInteger privateKey, ECPointFormat pointFormat) {
        if (group.isCurve() || group.isGrease()) {
            EllipticCurve curve = CurveFactory.getCurve(group);
            if (group.isStandardCurve() || group.isGrease()) {
                Point publicKey = curve.mult(privateKey, curve.getBasePoint());
                return PointFormatter.formatToByteArray(group, publicKey, pointFormat);
            } else {
                RFC7748Curve rfcCurve = (RFC7748Curve) curve;
                return rfcCurve.computePublicKey(privateKey);
            }
        } else if (group != NamedGroup.EXPLICIT_CHAR2 && group != NamedGroup.EXPLICIT_PRIME) {
            FFDHEGroup ffdheGroup = GroupFactory.getGroup(group);
            BigInteger publicKey = ffdheGroup.getG().modPow(privateKey.abs(), ffdheGroup.getP().abs());
            return ArrayConverter.bigIntegerToNullPaddedByteArray(publicKey,
                ffdheGroup.getP().bitLength() / Bits.IN_A_BYTE);
        } else {
            throw new IllegalArgumentException("Cannot create Public Key for group " + group.name());
        }
    }

    public static byte[] computeSharedSecret(NamedGroup group, byte[] privateKey, byte[] publicKey) {
        return KeyShareCalculator.computeSharedSecret(group, new BigInteger(privateKey), publicKey);
    }

    public static byte[] computeSharedSecret(NamedGroup group, BigInteger privateKey, byte[] publicKey) {
        if (group.isCurve()) {
            EllipticCurve curve = CurveFactory.getCurve(group);
            Point publicPoint = PointFormatter.formatFromByteArray(group, publicKey);
            switch (group) {
                case ECDH_X25519:
                case ECDH_X448:
                    RFC7748Curve rfcCurve = (RFC7748Curve) curve;
                    return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicPoint);
                case SECP160K1:
                case SECP160R1:
                case SECP160R2:
                case SECP192K1:
                case SECP192R1:
                case SECP224K1:
                case SECP224R1:
                case SECP256K1:
                case SECP256R1:
                case SECP384R1:
                case SECP521R1:
                case SECT163K1:
                case SECT163R1:
                case SECT163R2:
                case SECT193R1:
                case SECT193R2:
                case SECT233K1:
                case SECT233R1:
                case SECT239K1:
                case SECT283K1:
                case SECT283R1:
                case SECT409K1:
                case SECT409R1:
                case SECT571K1:
                case SECT571R1:
                    Point sharedPoint = curve.mult(privateKey, publicPoint);
                    int elementLength =
                        ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
                    return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getFieldX().getData(),
                        elementLength);
                default:
                    throw new UnsupportedOperationException("KeyShare type " + group + " is unsupported");
            }
        } else {
            FFDHEGroup ffdheGroup = GroupFactory.getGroup(group);
            BigInteger sharedElement = new BigInteger(1, publicKey).modPow(privateKey.abs(), ffdheGroup.getP().abs());
            return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedElement,
                ffdheGroup.getP().bitLength() / Bits.IN_A_BYTE);
        }
    }
}
