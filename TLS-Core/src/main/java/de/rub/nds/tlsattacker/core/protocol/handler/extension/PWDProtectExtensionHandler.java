/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.GroupParameters;
import de.rub.nds.protocol.crypto.CyclicGroup;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256R1;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.IllegalBlockSizeException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

public class PWDProtectExtensionHandler extends ExtensionHandler<PWDProtectExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PWDProtectExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(PWDProtectExtensionMessage message) {
        if (tlsContext.getChooser().getConnectionEndType() == ConnectionEndType.CLIENT) {
            tlsContext.setClientPWDUsername(tlsContext.getConfig().getDefaultClientPWDUsername());
            return;
        }
        GroupParameters<?> parameters =
                tlsContext.getConfig().getDefaultPWDProtectGroup().getGroupParameters();
        // decrypt protected username
        CyclicGroup<?> group = parameters.getGroup();
        HKDFAlgorithm hkdfAlgorithm;
        if (parameters.getElementSizeBits() <= 256) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (parameters.getElementSizeBits() <= 384) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA384;
        } else {
            LOGGER.warn("Missing HKDF algorithm for curves larger than 384 bits");
            return;
        }

        byte[] protectedUsername = message.getUsername().getValue();

        BigInteger clientPublicKeyX =
                new BigInteger(
                        1,
                        Arrays.copyOfRange(protectedUsername, 0, parameters.getElementSizeBytes()));
        // y^2 = (x^3 + x*val + b) mod p
        EllipticCurve curve;
        if (group instanceof EllipticCurve) {
            curve = (EllipticCurve) group;
        } else {
            LOGGER.warn(
                    "Original group is not an EllipticCurve ({}), using SecP256R1Curve",
                    parameters);
            curve = new EllipticCurveSECP256R1();
        }
        Point clientPublicKey = curve.createAPointOnCurve(clientPublicKeyX);
        BigInteger sharedSecret =
                curve.mult(
                                tlsContext.getConfig().getDefaultServerPWDProtectPrivateKey(),
                                clientPublicKey)
                        .getFieldX()
                        .getData();

        try {
            byte[] key =
                    HKDFunction.expand(
                            hkdfAlgorithm,
                            HKDFunction.extract(
                                    hkdfAlgorithm,
                                    null,
                                    DataConverter.bigIntegerToByteArray(sharedSecret)),
                            new byte[0],
                            parameters.getElementSizeBytes());

            byte[] ctrKey = Arrays.copyOfRange(key, 0, key.length / 2);
            byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);
            byte[] encryptedUsername =
                    Arrays.copyOfRange(
                            protectedUsername,
                            parameters.getElementSizeBytes(),
                            protectedUsername.length);
            SivMode aesSIV = new SivMode();
            String username =
                    new String(
                            aesSIV.decrypt(ctrKey, macKey, encryptedUsername),
                            StandardCharsets.ISO_8859_1);
            tlsContext.setClientPWDUsername(username);
            LOGGER.debug("Username: {}", tlsContext.getClientPWDUsername());
        } catch (IllegalBlockSizeException | UnauthenticCiphertextException | CryptoException e) {
            LOGGER.warn("Failed to decrypt username: {}", e.getMessage());
        }
    }
}
