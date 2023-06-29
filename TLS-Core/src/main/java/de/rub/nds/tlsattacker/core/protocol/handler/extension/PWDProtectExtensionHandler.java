/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HKDFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.HKDFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.util.Arrays;
import javax.crypto.IllegalBlockSizeException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
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

        // decrypt protected username
        ECCurve curve =
                ECNamedCurveTable.getParameterSpec(
                                tlsContext.getConfig().getDefaultPWDProtectGroup().getJavaName())
                        .getCurve();
        BigInteger prime = curve.getField().getCharacteristic();
        HKDFAlgorithm hkdfAlgorithm;
        if (curve.getFieldSize() <= 256) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA256;
        } else if (curve.getFieldSize() <= 384) {
            hkdfAlgorithm = HKDFAlgorithm.TLS_HKDF_SHA384;
        } else {
            LOGGER.warn("Missing HKDF algorithm for curves larger than 384 bits");
            return;
        }

        byte[] protectedUsername = message.getUsername().getValue();

        BigInteger clientPublicKeyX =
                new BigInteger(
                        1, Arrays.copyOfRange(protectedUsername, 0, curve.getFieldSize() / 8));
        // y^2 = (x^3 + x*val + b) mod p
        BigInteger clientPublicKeyYSquared =
                clientPublicKeyX
                        .pow(3)
                        .add(clientPublicKeyX.multiply(curve.getA().toBigInteger()))
                        .add(curve.getB().toBigInteger())
                        .mod(prime);
        // y = y^((p+1)/4) mod p = sqrt(y)
        BigInteger clientPublicKeyY =
                clientPublicKeyYSquared.modPow(prime.add(BigInteger.ONE).shiftRight(2), prime);
        ECPoint clientPublicKey = curve.createPoint(clientPublicKeyX, clientPublicKeyY);
        BigInteger sharedSecret =
                clientPublicKey
                        .multiply(tlsContext.getConfig().getDefaultServerPWDProtectPrivateKey())
                        .normalize()
                        .getXCoord()
                        .toBigInteger();
        try {
            byte[] key =
                    HKDFunction.expand(
                            hkdfAlgorithm,
                            HKDFunction.extract(
                                    hkdfAlgorithm,
                                    null,
                                    ArrayConverter.bigIntegerToByteArray(sharedSecret)),
                            new byte[0],
                            curve.getFieldSize() / Bits.IN_A_BYTE);

            byte[] ctrKey = Arrays.copyOfRange(key, 0, key.length / 2);
            byte[] macKey = Arrays.copyOfRange(key, key.length / 2, key.length);
            byte[] encryptedUsername =
                    Arrays.copyOfRange(
                            protectedUsername,
                            curve.getFieldSize() / Bits.IN_A_BYTE,
                            protectedUsername.length);
            SivMode aesSIV = new SivMode();
            String username = new String(aesSIV.decrypt(ctrKey, macKey, encryptedUsername));
            tlsContext.setClientPWDUsername(username);
            LOGGER.debug("Username: " + tlsContext.getClientPWDUsername());
        } catch (IllegalBlockSizeException | UnauthenticCiphertextException | CryptoException e) {
            LOGGER.warn("Failed to decrypt username: " + e.getMessage());
        }
    }
}
