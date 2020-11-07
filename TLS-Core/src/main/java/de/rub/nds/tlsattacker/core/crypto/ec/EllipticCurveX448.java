/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.crypto.ec;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.commons.lang3.ArrayUtils;

/**
 * X448
 */
public class EllipticCurveX448 extends RFC7748Curve {

    public EllipticCurveX448() {
        super(
            new BigInteger("262A6", 16),
            new BigInteger("1", 16),
            new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                16),
            new BigInteger("5", 16),
            new BigInteger(
                "7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC28DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
                16),
            new BigInteger(
                "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
                16));
    }

    public BigInteger decodeScalar(BigInteger scalar) {
        byte[] scalarA =
            ArrayConverter.bigIntegerToNullPaddedByteArray(scalar,
                ArrayConverter.bigIntegerToByteArray(getModulus()).length);
        scalarA[0] = (byte) (scalarA[0] & 252);
        scalarA[55] = (byte) (scalarA[55] | 128);

        ArrayUtils.reverse(scalarA);
        return new BigInteger(1, scalarA);
    }

    public BigInteger decodeCoordinate(BigInteger encCoordinate) {
        byte[] coordinate =
            ArrayConverter.bigIntegerToNullPaddedByteArray(encCoordinate,
                ArrayConverter.bigIntegerToByteArray(getModulus()).length);
        ArrayUtils.reverse(coordinate);

        return new BigInteger(1, coordinate).mod(getModulus());
    }

    public byte[] encodeCoordinate(BigInteger coordinate) {
        byte[] xEnc =
            ArrayConverter.bigIntegerToNullPaddedByteArray(coordinate,
                ArrayConverter.bigIntegerToByteArray(getModulus()).length);
        ArrayUtils.reverse(xEnc);
        return xEnc;
    }
}
