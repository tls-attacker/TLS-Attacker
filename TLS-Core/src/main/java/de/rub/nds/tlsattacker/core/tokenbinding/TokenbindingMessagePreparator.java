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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.tls.ECCurveType;
import org.bouncycastle.crypto.tls.TlsECCUtils;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenbindingMessagePreparator extends ProtocolMessagePreparator<TokenBindingMessage> {

    private TokenBindingMessage message;

    public TokenbindingMessagePreparator(Chooser chooser, TokenBindingMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        PrivateKey key;
        message.setTokenbindingType(chooser.getConfig().getDefaultTokenBindingType().getTokenBindingTypeValue());
        message.setKeyParameter(chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0).getValue());
        if (chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0) == TokenBindingKeyParameters.ECDSAP256) {
            ECDomainParameters generateEcParameters = generateEcParameters();
            AsymmetricCipherKeyPair keyPair = TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(),
                    generateEcParameters);
            ECPublicKeyParameters publicParams = (ECPublicKeyParameters) keyPair.getPublic();
            ECPrivateKeyParameters privateParams = (ECPrivateKeyParameters) keyPair.getPrivate();

            CustomECPoint point = new CustomECPoint(publicParams.getQ().getRawXCoord().toBigInteger(), publicParams
                    .getQ().getRawYCoord().toBigInteger());
            message.setPoint(ArrayConverter.concatenate(point.getX().toByteArray(), point.getY().toByteArray()));
            message.setPointLength(message.getPoint().getValue().length);
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            signer.init(true, privateParams);
            BigInteger[] signature = signer.generateSignature(generateToBeSigned());
            message.setSignature(ArrayConverter.concatenate(signature[0].toByteArray(), signature[1].toByteArray()));
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
