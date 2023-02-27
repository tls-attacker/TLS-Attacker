/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.protocol.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] createPublicKey(
            NamedGroup group, BigInteger privateKey, ECPointFormat pointFormat) {
        if (group.isCurve()) {
            EllipticCurve curve =
                    ((NamedEllipticCurveParameters) group.getGroupParameters()).getCurve();
            if (group.isShortWeierstrass() || group.isGrease()) {
                Point publicKey = curve.mult(privateKey, curve.getBasePoint());
                return PointFormatter.formatToByteArray(
                        (NamedEllipticCurveParameters) (group.getGroupParameters()),
                        publicKey,
                        pointFormat.getFormat());
            } else {
                RFC7748Curve rfcCurve = (RFC7748Curve) curve;
                return rfcCurve.computePublicKey(privateKey);
            }
        } else if (group.isDhGroup()) {
            FFDHEGroup ffdheGroup = (FFDHEGroup) group.getGroupParameters();
            BigInteger publicKey =
                    ffdheGroup.getG().modPow(privateKey.abs(), ffdheGroup.getP().abs());
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    publicKey, ffdheGroup.getP().bitLength() / Bits.IN_A_BYTE);
        } else {
            LOGGER.warn("Cannot create Public Key for group {}", group.name());
            return new byte[0];
        }
    }

    public static byte[] computeSharedSecret(
            NamedGroup group, BigInteger privateKey, byte[] publicKey) {
        System.out.println("Group; " + group.name());
        System.out.println("PrivateKey; " + privateKey);
        System.out.println("PublicKey; " + ArrayConverter.bytesToHexString(publicKey));

        if (group.isDhGroup()) {
            return computeDhSharedSecret(group, privateKey, new BigInteger(1, publicKey));
        } else if (group.isEcGroup()) {

            NamedEllipticCurveParameters parameters =
                    (NamedEllipticCurveParameters) group.getGroupParameters();
            Point point;
            point = PointFormatter.formatFromByteArray(parameters, publicKey);

            return computeEcSharedSecret(group, privateKey, point);
        } else {
            LOGGER.warn(
                    "Not sure how to compute shared secret for with: {} - using new byte[0] instead.",
                    group.name());
            return new byte[0];
        }
    }

    public static byte[] computeDhSharedSecret(
            NamedGroup group, BigInteger privateKey, BigInteger publicKey) {
        if (!group.isDhGroup()) {
            throw new IllegalArgumentException(
                    "Cannot compute dh shared secret for non ffdhe group");
        }
        BigInteger modulus = ((FFDHEGroup) group.getGroupParameters()).getP();
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                publicKey.modPow(privateKey, modulus), group.getGroupParameters().getElementSize());
    }

    public static byte[] computeEcSharedSecret(
            NamedGroup group, BigInteger privateKey, Point publicKey) {
        if (!group.isEcGroup()) {
            throw new IllegalArgumentException("Cannot compute ec shared secret for non ec group");
        }
        NamedEllipticCurveParameters parameters =
                (NamedEllipticCurveParameters) group.getGroupParameters();
        EllipticCurve curve = parameters.getCurve();
        if (group == NamedGroup.ECDH_X25519 || group == NamedGroup.ECDH_X448) {
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;
            return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicKey);
        }
        Point sharedPoint = curve.mult(privateKey, publicKey);
        int elementLength =
                ArrayConverter.bigIntegerToByteArray(sharedPoint.getFieldX().getModulus()).length;
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                sharedPoint.getFieldX().getData(), elementLength);
    }
}
