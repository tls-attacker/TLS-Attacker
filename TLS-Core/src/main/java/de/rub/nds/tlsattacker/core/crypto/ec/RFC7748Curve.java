/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import org.bouncycastle.util.Arrays;

/**
 *
 */
public abstract class RFC7748Curve extends SimulatedMontgomeryCurve {

    protected RFC7748Curve(BigInteger a, BigInteger b, BigInteger modulus, BigInteger basePointX,
            BigInteger basePointY, BigInteger basePointOrder) {
        super(a, b, modulus, basePointX, basePointY, basePointOrder);
    }

    public abstract BigInteger decodeScalar(BigInteger scalar);

    public abstract BigInteger decodeCoordinate(BigInteger encCoordinate);

    public abstract byte[] encodeCoordinate(BigInteger coordinate);

    public byte[] computePublicKey(BigInteger privateKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedKey = decodeScalar(privateKey);
        Point publicPoint = mult(decodedKey, getBasePoint());

        return encodeCoordinate(publicPoint.getX().getData());
    }

    public byte[] computeSharedSecret(BigInteger privateKey, byte[] publicKey) {
        privateKey = reduceLongKey(privateKey);
        BigInteger decodedCoord = decodeCoordinate(new BigInteger(1, publicKey));
        BigInteger decodedKey = decodeScalar(privateKey);

        Point publicPoint = createAPointOnCurve(decodedCoord);
        Point sharedPoint = mult(decodedKey, publicPoint);

        return encodeCoordinate(sharedPoint.getX().getData());
    }

    public byte[] computeSharedSecret(BigInteger privateKey, Point publicKey) {
        byte[] pkBytes = ArrayConverter.bigIntegerToNullPaddedByteArray(publicKey.getX().getData(),
                ArrayConverter.bigIntegerToByteArray(getModulus()).length);
        return computeSharedSecret(privateKey, pkBytes);
    }

    public byte[] computeSharedSecretDecodedPoint(BigInteger privateKey, Point publicKey) {
        byte[] reEncoded = encodeCoordinate(publicKey.getX().getData());
        return computeSharedSecret(privateKey, reEncoded);
    }

    public BigInteger reduceLongKey(BigInteger key) {
        byte[] keyBytes = key.toByteArray();
        if (keyBytes.length > ArrayConverter.bigIntegerToByteArray(getModulus()).length) {
            keyBytes = Arrays.copyOfRange(keyBytes, 0, ArrayConverter.bigIntegerToByteArray(getModulus()).length);
            return new BigInteger(1, keyBytes);
        } else {
            return key;
        }
    }
}
