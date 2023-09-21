/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.EcCurveEquationType;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.protocol.crypto.ffdh.FFDHGroup;
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
        if (group.isGrease()) {
            return new byte[0];
        }
        if (group.isEcGroup()) {
            EllipticCurve curve =
                    ((NamedEllipticCurveParameters) group.getGroupParameters()).getCurve();
            if (group.isShortWeierstrass()) {
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
            FFDHGroup ffdheGroup = (FFDHGroup) group.getGroupParameters();
            BigInteger publicKey =
                    ffdheGroup
                            .getGenerator()
                            .modPow(privateKey.abs(), ffdheGroup.getModulus().abs());
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    publicKey, ffdheGroup.getModulus().bitLength() / Bits.IN_A_BYTE);
        } else {
            LOGGER.warn("Cannot create Public Key for group {}", group.name());
            return new byte[0];
        }
    }

    public static byte[] computeSharedSecret(
            NamedGroup group, BigInteger privateKey, byte[] publicKey) {
        if (group.isGrease()) {
            return new byte[0];
        }
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

    /**
     * Computes the shared secret for a DH key exchange. Leading zero bytes of the shared secret are
     * maintained.
     *
     * @param group The group that should be used
     * @param privateKey The private key that should be used
     * @param publicKey The public key that should be used.
     * @return The shared secret with leading zero bytes.
     */
    public static byte[] computeDhSharedSecret(
            NamedGroup group, BigInteger privateKey, BigInteger publicKey) {
        if (!group.isDhGroup()) {
            throw new IllegalArgumentException(
                    "Cannot compute dh shared secret for non ffdhe group");
        }
        BigInteger modulus = ((FFDHGroup) group.getGroupParameters()).getModulus();
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                publicKey.modPow(privateKey, modulus),
                group.getGroupParameters().getElementSizeBytes());
    }

    /**
     * Computes the shared secret for an ECDH key exchange. Leading zero bytes of the shared secret
     * are maintained.
     *
     * @param group The group that should be used
     * @param privateKey The private key that should be used
     * @param publicKey The public key that should be used.
     * @return The shared secret with leading zero bytes.
     */
    public static byte[] computeEcSharedSecret(
            NamedGroup group, BigInteger privateKey, Point publicKey) {
        if (!group.isEcGroup()) {
            throw new IllegalArgumentException("Cannot compute ec shared secret for non ec group");
        }
        NamedEllipticCurveParameters parameters =
                (NamedEllipticCurveParameters) group.getGroupParameters();
        EllipticCurve curve = parameters.getCurve();
        if (parameters.getEquationType() == EcCurveEquationType.MONTGOMERY) {
            if (curve instanceof RFC7748Curve) {
                RFC7748Curve rfcCurve = (RFC7748Curve) curve;
                return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicKey);
            } else {
                throw new UnsupportedOperationException(
                        "Cannot compute shared secret for non RFC7748 curve. Not implemented yet");
            }
        }
        Point sharedPoint = curve.mult(privateKey, publicKey);
        int elementLength = parameters.getElementSizeBytes();
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                sharedPoint.getFieldX().getData(), elementLength);
    }
}
