/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cryptomator.siv.SivMode;

public class PWDProtectExtensionPreparator extends ExtensionPreparator<PWDProtectExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDProtectExtensionMessage msg;

    public PWDProtectExtensionPreparator(Chooser chooser, PWDProtectExtensionMessage message,
            PWDProtectExtensionSerializer serializer) {
        super(chooser, message, serializer);
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

        BigInteger clientPublicKey = curve.mult(config.getDefaultServerPWDProtectRandomSecret(), generator).getX()
                .getData();
        BigInteger sharedSecret = curve.mult(config.getDefaultServerPWDProtectRandomSecret(), serverPublicKey).getX()
                .getData();

        byte[] key = HKDFunction.expand(hkdfAlgorithm,
                HKDFunction.extract(hkdfAlgorithm, null, ArrayConverter.bigIntegerToByteArray(sharedSecret)),
                new byte[0], curve.getModulus().bitLength() / 8);
        LOGGER.debug("Username encryption key: " + ArrayConverter.bytesToHexString(key));

        byte[] ctrKey = Arrays.copyOfRange(key, 0, key.length / 2);
        byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);
        SivMode AES_SIV = new SivMode();
        byte[] protectedUsername = AES_SIV.encrypt(ctrKey, macKey, chooser.getClientPWDUsername().getBytes());
        msg.setUsername(ArrayConverter.concatenate(
                ArrayConverter.bigIntegerToByteArray(clientPublicKey, curve.getModulus().bitLength() / 8, true),
                protectedUsername));
        LOGGER.debug("Username: " + ArrayConverter.bytesToHexString(msg.getUsername()));
    }

    private void prepareUsernameLength(PWDProtectExtensionMessage msg) {
        msg.setUsernameLength(msg.getUsername().getValue().length);
        LOGGER.debug("UsernameLength: " + msg.getUsernameLength().getValue());
    }
}
