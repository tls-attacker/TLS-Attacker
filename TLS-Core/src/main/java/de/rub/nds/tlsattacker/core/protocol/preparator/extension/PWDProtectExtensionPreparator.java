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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.PWDProtectExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.cryptomator.siv.SivMode;

import java.math.BigInteger;
import java.util.Arrays;

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
        ECCurve curve = ECNamedCurveTable.getParameterSpec(config.getDefaultPWDProtectGroup().getJavaName()).getCurve();
        ECPoint generator = ECNamedCurveTable.getParameterSpec(config.getDefaultPWDProtectGroup().getJavaName()).getG();
        ECPoint serverPublicKey = curve.createPoint(config.getDefaultServerPWDProtectPublicKey().getX(), config
                .getDefaultServerPWDProtectPublicKey().getY());

        HKDFAlgorithm hkdfAlgorithm;
        if (curve.getFieldSize() <= 256) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (curve.getFieldSize() <= 384) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA384;
        } else {
            throw new CryptoException("Missing HKDF algorithm for curves larger than 384 bits");
        }

        BigInteger clientPublicKey = generator.multiply(config.getDefaultServerPWDProtectRandomSecret()).normalize()
                .getXCoord().toBigInteger();
        BigInteger sharedSecret = serverPublicKey.multiply(config.getDefaultServerPWDProtectRandomSecret()).normalize()
                .getXCoord().toBigInteger();

        byte[] key = HKDFunction.expand(hkdfAlgorithm,
                HKDFunction.extract(hkdfAlgorithm, null, ArrayConverter.bigIntegerToByteArray(sharedSecret)),
                new byte[0], curve.getFieldSize() / 8);
        LOGGER.debug("Username encryption key: " + ArrayConverter.bytesToHexString(key));

        byte[] ctrKey = Arrays.copyOfRange(key, 0, key.length / 2);
        byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);
        SivMode AES_SIV = new SivMode();
        byte[] protectedUsername = AES_SIV.encrypt(ctrKey, macKey, chooser.getClientPWDUsername().getBytes());
        msg.setUsername(ArrayConverter.concatenate(
                ArrayConverter.bigIntegerToByteArray(clientPublicKey, curve.getFieldSize() / 8, true),
                protectedUsername));
        LOGGER.debug("Username: " + ArrayConverter.bytesToHexString(msg.getUsername()));
    }

    private void prepareUsernameLength(PWDProtectExtensionMessage msg) {
        msg.setUsernameLength(msg.getUsername().getValue().length);
        LOGGER.debug("UsernameLength: " + msg.getUsernameLength().getValue());
    }
}
