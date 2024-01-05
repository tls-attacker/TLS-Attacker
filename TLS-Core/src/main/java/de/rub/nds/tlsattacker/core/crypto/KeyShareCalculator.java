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
import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.protocol.crypto.ffdh.FfdhGroup;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] createPublicKey(
            NamedGroup namedGroup, BigInteger privateKey, ECPointFormat pointFormat) {
        if (namedGroup.isGrease()) {
            return new byte[0];
        }
        CyclicGroup<?> group = namedGroup.getGroupParameters().getGroup();

        if (namedGroup.isEcGroup()) {
            if (namedGroup.isShortWeierstrass()) {
                Point publicKey = (Point) group.nTimesGroupOperationOnGenerator(privateKey);
                return PointFormatter.formatToByteArray(
                        namedGroup.getGroupParameters(), publicKey, pointFormat.getFormat());
            } else {
                RFC7748Curve rfcCurve = (RFC7748Curve) group;
                return rfcCurve.computePublicKey(privateKey);
            }
        } else if (namedGroup.isDhGroup()) {
            BigInteger publicKey = (BigInteger) group.nTimesGroupOperationOnGenerator(privateKey);
            return ArrayConverter.bigIntegerToNullPaddedByteArray(
                    publicKey, ((FfdhGroup) group).getParameters().getElementSizeBytes());
        } else {
            LOGGER.warn("Cannot create Public Key for group {}", namedGroup.name());
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
            Point point = PointFormatter.formatFromByteArray(group.getGroupParameters(), publicKey);

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
        CyclicGroup<?> cyclicGroup = group.getGroupParameters().getGroup();
        BigInteger sharedSecret;
        if (cyclicGroup instanceof FfdhGroup) {
            sharedSecret = ((FfdhGroup) cyclicGroup).nTimesGroupOperation(publicKey, privateKey);
        } else {
            throw new IllegalArgumentException(
                    "Cannot compute dh shared secret for non ffdhe group");
        }
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                sharedSecret, group.getGroupParameters().getElementSizeBytes());
    }

    /**
     * Computes the shared secret for an ECDH key exchange. Leading zero bytes of the shared secret
     * are maintained.
     *
     * @param namedGroup The group that should be used
     * @param privateKey The private key that should be used
     * @param publicKey The public key that should be used.
     * @return The shared secret with leading zero bytes.
     */
    public static byte[] computeEcSharedSecret(
            NamedGroup namedGroup, BigInteger privateKey, Point publicKey) {
        if (!(namedGroup.getGroupParameters().getGroup() instanceof EllipticCurve)) {
            throw new IllegalArgumentException("Cannot compute ec shared secret for non ec group");
        }
        GroupParameters<?> parameters = namedGroup.getGroupParameters();
        EllipticCurve curve = (EllipticCurve) parameters.getGroup();
        if (curve instanceof RFC7748Curve) {
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;
            return rfcCurve.computeSharedSecretFromDecodedPoint(privateKey, publicKey);
        }

        Point sharedPoint = curve.nTimesGroupOperation(publicKey, privateKey);
        int elementLength = parameters.getElementSizeBytes();
        return ArrayConverter.bigIntegerToNullPaddedByteArray(
                sharedPoint.getFieldX().getData(), elementLength);
    }
}
