/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

/** */
public abstract class RFC7748Curve extends SimulatedMontgomeryCurve {

    private static final Logger LOGGER = LogManager.getLogger();

    protected RFC7748Curve(
            BigInteger a,
            BigInteger b,
            BigInteger modulus,
            BigInteger basePointX,
            BigInteger basePointY,
            BigInteger basePointOrder) {
        super(a, b, modulus, basePointX, basePointY, basePointOrder);
    }

    public abstract BigInteger decodeScalar(BigInteger scalar);

    public abstract BigInteger decodeCoordinate(BigInteger encCoordinate);

    public abstract byte[] encodeCoordinate(BigInteger coordinate);

    public byte[] computePublicKey(BigInteger privateKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedKey = decodeScalar(privateKey);
        Point publicPoint = mult(decodedKey, getBasePoint());

        return encodeCoordinate(publicPoint.getFieldX().getData());
    }

    private byte[] computeSharedSecret(BigInteger privateKey, byte[] publicKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedCoord = decodeCoordinate(new BigInteger(1, publicKey));
        BigInteger decodedKey = decodeScalar(privateKey);

        Point publicPoint = createAPointOnCurve(decodedCoord);
        if (publicPoint == null) {
            LOGGER.warn("Could not create a point on curve. Using non-point");
            publicPoint = getPoint(BigInteger.ZERO, BigInteger.ZERO);
        }
        Point sharedPoint = mult(decodedKey, publicPoint);
        if (sharedPoint.getFieldX() == null) {
            LOGGER.warn(
                    "Cannot encode point in infinity. Using X coordinate of base point as shared secret");
            return encodeCoordinate(getBasePoint().getFieldX().getData());
        }
        return encodeCoordinate(sharedPoint.getFieldX().getData());
    }

    public byte[] computeSharedSecretFromDecodedPoint(BigInteger privateKey, Point publicKey) {
        byte[] reEncoded = encodeCoordinate(publicKey.getFieldX().getData());
        return computeSharedSecret(privateKey, reEncoded);
    }

    public BigInteger reduceLongKey(BigInteger key) {
        byte[] keyBytes = key.toByteArray();
        if (keyBytes.length > ArrayConverter.bigIntegerToByteArray(getModulus()).length) {
            keyBytes =
                    Arrays.copyOfRange(
                            keyBytes, 0, ArrayConverter.bigIntegerToByteArray(getModulus()).length);
            return new BigInteger(1, keyBytes);
        } else {
            return key;
        }
    }
}
