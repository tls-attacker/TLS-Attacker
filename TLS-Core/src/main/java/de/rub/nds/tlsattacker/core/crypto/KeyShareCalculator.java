/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareCalculator {

    private static final Logger LOGGER = LogManager.getLogger();

    public static Point createPublicKey(NamedGroup group, BigInteger privateKey) {
        if (!group.isStandardCurve()) {
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
        if (group == NamedGroup.ECDH_X25519) {
            return ForgivingX25519Curve.computePublicKey(privateKey);
        } else if (group == NamedGroup.ECDH_X448) {
            return ForgivingX448Curve.computePublicKey(privateKey);
        } else {
            throw new UnsupportedOperationException("Unknown MontgomeryGroup: " + group.name());
        }
    }

    private byte[] computeSharedSecret(KeyShareEntry keyShare) {
        switch (keyShare.getGroupConfig()) {
            case ECDH_X25519:
                byte[] privateKey = keyShare.getPrivateKey().toByteArray();
                byte[] publicKey = keyShare.getPublicKey().getValue();
                return ForgivingX25519Curve.computeSharedSecret(privateKey, publicKey);
            case ECDH_X448:
                privateKey = keyShare.getPrivateKey().toByteArray();
                publicKey = keyShare.getPublicKey().getValue();
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
                EllipticCurve curve = CurveFactory.getCurve(keyShare.getGroupConfig());
                Point publicKeyPoint = PointFormatter.formatFromByteArray(keyShare.getGroupConfig(), keyShare
                        .getPublicKey().getValue());
                Point sharedPoint = curve.mult(keyShare.getPrivateKey(), publicKeyPoint);
                int elementLenght = ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length;
                return ArrayConverter.bigIntegerToNullPaddedByteArray(sharedPoint.getX().getData(), elementLenght);
            default:
                throw new UnsupportedOperationException("KeyShare type " + keyShare.getGroupConfig()
                        + " is unsupported");
        }
    }

}
