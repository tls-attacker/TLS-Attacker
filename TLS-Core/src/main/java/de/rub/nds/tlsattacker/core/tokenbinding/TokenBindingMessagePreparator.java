/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;

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
            EllipticCurve curve = CurveFactory.getCurve(NamedGroup.SECP256R1);
            BigInteger privateKey = chooser.getConfig().getDefaultTokenBindingEcPrivateKey();
            LOGGER.debug("Using private Key:" + privateKey);
            Point publicKey = curve.mult(privateKey, curve.getBasePoint());

            message.setPoint(PointFormatter.toRawFormat(publicKey));
            message.setPointLength(message.getPoint().getValue().length);
            ParametersWithRandom params =
                    new ParametersWithRandom(
                            new ECPrivateKeyParameters(privateKey, generateEcParameters()),
                            new BadRandom(new Random(0), new byte[0]));
            ECDSASigner signer = new ECDSASigner();
            signer.init(true, params);
            MessageDigest dig;
            try {
                dig = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException ex) {
                throw new PreparationException("Could not create SHA-256 digest", ex);
            }
            dig.update(generateToBeSigned());
            BigInteger[] signature = signer.generateSignature(dig.digest());

            message.setSignature(
                    ArrayConverter.concatenate(
                            ArrayConverter.bigIntegerToByteArray(signature[0]),
                            ArrayConverter.bigIntegerToByteArray(signature[1])));
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

    private ECDomainParameters generateEcParameters() {
        NamedGroup[] groups = new NamedGroup[] {NamedGroup.SECP256R1};
        ECPointFormat[] formats = new ECPointFormat[] {ECPointFormat.UNCOMPRESSED};
        InputStream is =
                new ByteArrayInputStream(
                        ArrayConverter.concatenate(
                                new byte[] {EllipticCurveType.NAMED_CURVE.getValue()},
                                NamedGroup.SECP256R1.getValue()));
        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(groups, formats, is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }

        return ecParams;
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
