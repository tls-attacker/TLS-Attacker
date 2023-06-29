/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cryptomator.siv.SivMode;

public class PWDProtectExtensionPreparator extends ExtensionPreparator<PWDProtectExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDProtectExtensionMessage msg;

    public PWDProtectExtensionPreparator(Chooser chooser, PWDProtectExtensionMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing PWDProtectExtension");
        try {
            prepareUsername(msg);
        } catch (CryptoException e) {
            throw new PreparationException("Failed to encrypt username", e);
        }
        prepareUsernameLength(msg);
    }

    private void prepareUsername(PWDProtectExtensionMessage msg) throws CryptoException {
        Config config = chooser.getConfig();
        EllipticCurve curve = CurveFactory.getCurve(config.getDefaultPWDProtectGroup());
        Point generator = curve.getBasePoint();
        Point serverPublicKey = config.getDefaultServerPWDProtectPublicKey();

        HKDFAlgorithm hkdfAlgorithm;
        if (curve.getModulus().bitLength() <= 256) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (curve.getModulus().bitLength() <= 384) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA384;
        } else {
            throw new CryptoException("Missing HKDF algorithm for curves larger than 384 bits");
        }

        Point multedPoint = curve.mult(config.getDefaultServerPWDProtectRandomSecret(), generator);
        BigInteger clientPublicKey;
        if (!multedPoint.isAtInfinity()) {
            clientPublicKey = multedPoint.getFieldX().getData();
        } else {
            LOGGER.warn(
                    "Computed intermediate value as point in infinity. Using Zero instead for X value");
            clientPublicKey = BigInteger.ZERO;
        }
        Point sharedPoint =
                curve.mult(config.getDefaultServerPWDProtectRandomSecret(), serverPublicKey);
        BigInteger sharedSecret;
        if (!sharedPoint.isAtInfinity()) {
            sharedSecret =
                    curve.mult(config.getDefaultServerPWDProtectRandomSecret(), serverPublicKey)
                            .getFieldX()
                            .getData();
        } else {
            LOGGER.warn(
                    "Computed shared secet as point in infinity. Using Zero instead for X value");
            sharedSecret = BigInteger.ZERO;
        }

        byte[] key =
                HKDFunction.expand(
                        hkdfAlgorithm,
                        HKDFunction.extract(
                                hkdfAlgorithm,
                                null,
                                ArrayConverter.bigIntegerToByteArray(sharedSecret)),
                        new byte[0],
                        curve.getModulus().bitLength() / Bits.IN_A_BYTE);
        LOGGER.debug("Username encryption key: {}", key);

        byte[] ctrKey = Arrays.copyOfRange(key, 0, key.length / 2);
        byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);
        if (ctrKey.length != 16 && ctrKey.length != 24 && ctrKey.length != 32) {
            LOGGER.warn("PWD ctrkey is of incorrect size. Padding to 16 byte");
            ctrKey = Arrays.copyOf(ctrKey, 16);
        }
        if (macKey.length != 16 && macKey.length != 24 && macKey.length != 32) {
            LOGGER.warn("PWD macKey is of incorrect size. Padding to 16 byte");
            macKey = Arrays.copyOf(macKey, 16);
        }
        SivMode aesSIV = new SivMode();
        byte[] protectedUsername =
                aesSIV.encrypt(
                        ctrKey,
                        macKey,
                        chooser.getClientPWDUsername().getBytes(StandardCharsets.ISO_8859_1));
        msg.setUsername(
                ArrayConverter.concatenate(
                        ArrayConverter.bigIntegerToByteArray(
                                clientPublicKey,
                                curve.getModulus().bitLength() / Bits.IN_A_BYTE,
                                true),
                        protectedUsername));
        LOGGER.debug("Username: {}", msg.getUsername());
    }

    private void prepareUsernameLength(PWDProtectExtensionMessage msg) {
        msg.setUsernameLength(msg.getUsername().getValue().length);
        LOGGER.debug("UsernameLength: " + msg.getUsernameLength().getValue());
    }
}
