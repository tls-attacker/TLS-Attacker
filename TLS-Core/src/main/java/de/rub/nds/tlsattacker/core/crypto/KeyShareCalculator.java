/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX448Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static List<NamedGroup> getImplemented() {
        List<NamedGroup> list = new LinkedList();
        list.add(NamedGroup.ECDH_X25519);
        list.add(NamedGroup.ECDH_X448);
        list.add(NamedGroup.SECP160K1);
        list.add(NamedGroup.SECP160R1);
        list.add(NamedGroup.SECP160R2);
        list.add(NamedGroup.SECP192K1);
        list.add(NamedGroup.SECP192R1);
        list.add(NamedGroup.SECP224K1);
        list.add(NamedGroup.SECP224R1);
        list.add(NamedGroup.SECP256K1);
        list.add(NamedGroup.SECP256R1);
        list.add(NamedGroup.SECP384R1);
        list.add(NamedGroup.SECP521R1);
        list.add(NamedGroup.SECT163K1);
        list.add(NamedGroup.SECT163R1);
        list.add(NamedGroup.SECT163R2);
        list.add(NamedGroup.SECT193R1);
        list.add(NamedGroup.SECT193R2);
        list.add(NamedGroup.SECT233K1);
        list.add(NamedGroup.SECT233R1);
        list.add(NamedGroup.SECT239K1);
        list.add(NamedGroup.SECT283K1);
        list.add(NamedGroup.SECT283R1);
        list.add(NamedGroup.SECT409K1);
        list.add(NamedGroup.SECT409R1);
        list.add(NamedGroup.SECT571K1);
        list.add(NamedGroup.SECT571R1);
        return list;
    }

    public static Point createPublicKey(NamedGroup group, BigInteger privateKey) {
        if (!group.isStandardCurve() && !group.isGrease()) {
            throw new IllegalArgumentException(
                "Cannot create ClassicEcPublicKey for group which is not a classic curve:" + group.name());
        }
        EllipticCurve curve = CurveFactory.getCurve(group);
        Point point = curve.mult(privateKey, curve.getBasePoint());
        return point;
    }

    public static byte[] createMontgomeryKeyShare(NamedGroup group, BigInteger privateKey) {
        if (!group.isCurve() || group.isStandardCurve()) {
            throw new IllegalArgumentException(
                "Cannot create ClassicEcPublicKey for group which is not a classic curve:" + group.name());
        }
        if (group == NamedGroup.ECDH_X25519 || group == NamedGroup.ECDH_X448) {
            EllipticCurve curve = CurveFactory.getCurve(group);
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;

            return rfcCurve.computePublicKey(privateKey);
        } else {
            throw new UnsupportedOperationException("Unknown MontgomeryGroup: " + group.name());
        }
    }

    public static byte[] computeSharedSecret(NamedGroup group, byte[] privateKey, byte[] publicKey) {
        return KeyShareCalculator.computeSharedSecret(group, new BigInteger(privateKey), publicKey);
    }

    public static byte[] computeSharedSecret(NamedGroup group, BigInteger privateKey, byte[] publicKey) {
        switch (group) {
            case ECDH_X25519:
                return ForgivingX25519Curve.computeSharedSecret(privateKey, publicKey);
            case ECDH_X448:
                return ForgivingX448Curve.computeSharedSecret(privateKey, publicKey);
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
                EllipticCurve curve = CurveFactory.getCurve(group);
                Point publicPoint = PointFormatter.formatFromByteArray(group, publicKey);
                Point sharedPoint = curve.mult(privateKey, publicPoint);
                int elementLength = ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
                return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getFieldX().getData(), elementLength);
            default:
                throw new UnsupportedOperationException("KeyShare type " + group + " is unsupported");
        }
    }
}
