/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import org.apache.commons.lang3.ArrayUtils;

/**
 * X25519
 */
public class EllipticCurveX25519 extends RFC7748Curve {

    @SuppressWarnings("SpellCheckingInspection")
    public EllipticCurveX25519() {
        super(new BigInteger("76D06", 16), new BigInteger("1", 16),
            new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16),
            new BigInteger("9", 16),
            new BigInteger("5F51E65E475F794B1FE122D388B72EB36DC2B28192839E4DD6163A5D81312C14", 16),
            new BigInteger("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16));
    }

    public BigInteger decodeScalar(BigInteger scalar) {
        byte[] scalarA = ArrayConverter.bigIntegerToByteArray(scalar,
            ArrayConverter.bigIntegerToByteArray(getModulus()).length, true);
        scalarA[0] = (byte) (scalarA[0] & 248);
        scalarA[31] = (byte) (scalarA[31] & 127);
        scalarA[31] = (byte) (scalarA[31] | 64);

        ArrayUtils.reverse(scalarA);
        return new BigInteger(1, scalarA);
    }

    public BigInteger decodeCoordinate(BigInteger encCoordinate) {
        byte[] coordinate = ArrayConverter.bigIntegerToByteArray(encCoordinate,
            ArrayConverter.bigIntegerToByteArray(getModulus()).length, true);
        coordinate[31] = (byte) (coordinate[31] & ((1 << 7) - 1));
        ArrayUtils.reverse(coordinate);

        return new BigInteger(1, coordinate).mod(getModulus());
    }

    public byte[] encodeCoordinate(BigInteger coordinate) {
        byte[] encX = ArrayConverter.bigIntegerToByteArray(coordinate,
            ArrayConverter.bigIntegerToByteArray(getModulus()).length, true);
        ArrayUtils.reverse(encX);
        return encX;
    }

}
