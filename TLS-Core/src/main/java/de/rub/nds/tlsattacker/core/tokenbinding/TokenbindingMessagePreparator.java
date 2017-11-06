/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.BadRandom;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.KeyGenerator;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.util.Random;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

public class TokenbindingMessagePreparator extends ProtocolMessagePreparator<TokenBindingMessage> {

    private TokenBindingMessage message;

    public TokenbindingMessagePreparator(Chooser chooser, TokenBindingMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        message.setTokenbindingType(chooser.getConfig().getDefaultTokenBindingType().getTokenBindingTypeValue());
        message.setKeyParameter(chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0).getValue());
        if (chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0) == TokenBindingKeyParameters.ECDSAP256) {
            ECDomainParameters generateEcParameters = generateEcParameters();
            ECPrivateKey tokenBindingECPrivateKey = KeyGenerator.getTokenBindingECPrivateKey(chooser);
            LOGGER.debug("Using private Key:" + tokenBindingECPrivateKey.getS());
            ECPoint publicKey = generateEcParameters.getG().multiply(tokenBindingECPrivateKey.getS());
            publicKey = publicKey.normalize();
            CustomECPoint point = new CustomECPoint(publicKey.getRawXCoord().toBigInteger(), publicKey.getRawYCoord()
                    .toBigInteger());
            message.setPoint(ArrayConverter.concatenate(point.getByteX(), point.getByteY()));
            message.setPointLength(message.getPoint().getValue().length);
            ParametersWithRandom params = new ParametersWithRandom(new ECPrivateKeyParameters(
                    tokenBindingECPrivateKey.getS(), generateEcParameters), new BadRandom(new Random(0), new byte[0]));
            ECDSASigner signer = new ECDSASigner();
            signer.init(true, params);
            MessageDigest dig = null;
            try {
                dig = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
            dig.update(generateToBeSigned());
            BigInteger[] signature = signer.generateSignature(dig.digest());

            message.setSignature(ArrayConverter.concatenate(CustomECPoint.toUnsignedByteArray(signature[0]),
                    CustomECPoint.toUnsignedByteArray(signature[1])));
        } else {
            message.setModulus(chooser.getConfig().getDefaultTokenBindingRsaModulus().toByteArray());
            message.setModulusLength(message.getModulus().getValue().length);
            message.setPublicExponent(chooser.getConfig().getDefaultTokenBindingRsaPublicKey().toByteArray());
            message.setPublicExponentLength(message.getPublicExponent().getValue().length);
        }
        TokenBindingMessageSerializer serializer = new TokenBindingMessageSerializer(message,
                chooser.getSelectedProtocolVersion());
        message.setKeyLength(serializer.serializeKey().length);
        message.setExtensionBytes(new byte[0]);
        message.setExtensionLength(message.getExtensionBytes().getValue().length);
        SignatureAndHashAlgorithm algorithm = new SignatureAndHashAlgorithm(SignatureAlgorithm.ECDSA,
                HashAlgorithm.SHA1);
        // message.setSignature(SignatureCalculator.generateSignature(chooser.getConfig()
        // .getDefaultTokenBindingKeyParameters().get(0), chooser,));
        message.setSignatureLength(message.getSignature().getValue().length);
        serializer = new TokenBindingMessageSerializer(message, ProtocolVersion.TLS12);
        message.setTokenbindingsLength(serializer.serializeBinding().length);
    }

    private byte[] generateToBeSigned() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(new byte[] { message.getTokenbindingType().getValue() });
            stream.write(new byte[] { message.getKeyParameter().getValue() });
            stream.write(TokenCalculator.calculateEKM(chooser, 32));
            return stream.toByteArray();
        } catch (IOException ex) {
            throw new PreparationException("Could not generate data to be Signed!", ex);
        }
    }

    private ECDomainParameters generateEcParameters() {
        NamedCurve[] curves = new NamedCurve[] { NamedCurve.SECP256R1 };
        ECPointFormat[] formats = new ECPointFormat[] { ECPointFormat.UNCOMPRESSED };
        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { EllipticCurveType.NAMED_CURVE.getValue() }, NamedCurve.SECP256R1.getValue()));
        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }

        return ecParams;
    }

}
