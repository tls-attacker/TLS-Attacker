/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.EllipticCurveSECP256R1;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.signature.EcdsaSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TokenBindingMessagePreparator extends ProtocolMessagePreparator<TokenBindingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TokenBindingMessage message;

    public TokenBindingMessagePreparator(Chooser chooser, TokenBindingMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setTokenbindingType(
                chooser.getConfig().getDefaultTokenBindingType().getTokenBindingTypeValue());
        message.setKeyParameter(
                chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0).getValue());
        if (chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0)
                == TokenBindingKeyParameters.ECDSAP256) {
            EllipticCurve curve = new EllipticCurveSECP256R1();
            BigInteger privateKey = chooser.getConfig().getDefaultTokenBindingEcPrivateKey();
            LOGGER.debug("Using private Key:" + privateKey);
            Point publicKey = curve.mult(privateKey, curve.getBasePoint());

            message.setPoint(PointFormatter.toRawFormat(publicKey));
            message.setPointLength(message.getPoint().getValue().length);

            byte[] signature =
                    generateSignature(SignatureAndHashAlgorithm.ECDSA_SHA256, generateToBeSigned());
            message.setSignature(signature);
        } else {
            message.setModulus(
                    chooser.getConfig().getDefaultTokenBindingRsaModulus().toByteArray());
            message.setModulusLength(message.getModulus().getValue().length);
            message.setPublicExponent(
                    chooser.getConfig().getDefaultTokenBindingRsaPublicKey().toByteArray());
            message.setPublicExponentLength(message.getPublicExponent().getValue().length);
            message.setSignature(new byte[0]);
        }
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(message);
        message.setKeyLength(serializer.serializeKey().length);
        message.setExtensionBytes(new byte[0]);
        message.setExtensionLength(message.getExtensionBytes().getValue().length);
        message.setSignatureLength(message.getSignature().getValue().length);
        serializer = new TokenBindingMessageSerializer(message);
        message.setTokenbindingsLength(serializer.serializeBinding().length);
    }

    private byte[] generateSignature(
            SignatureAndHashAlgorithm algorithm, byte[] toBeHashedAndSigned) {

        SignatureCalculator calculator = new SignatureCalculator();
        calculator.computeRawEcdsaSignature(
                (EcdsaSignatureComputations)
                        message.getSignatureComputations(SignatureAlgorithm.ECDSA),
                chooser.getConfig().getDefaultTokenBindingEcPrivateKey(),
                toBeHashedAndSigned,
                chooser.getConfig().getDefaultEcdsaNonce(),
                NamedEllipticCurveParameters.SECP256R1,
                HashAlgorithm.SHA256);
        return message.getSignatureComputations(algorithm.getSignatureAlgorithm())
                .getSignatureBytes()
                .getValue();
    }

    private byte[] generateToBeSigned() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(new byte[] {message.getTokenbindingType().getValue()});
            stream.write(new byte[] {message.getKeyParameter().getValue()});
            stream.write(TokenCalculator.calculateEKM(chooser, 32));
            return stream.toByteArray();
        } catch (IOException | CryptoException ex) {
            throw new PreparationException("Could not generate data to be Signed!", ex);
        }
    }
}
