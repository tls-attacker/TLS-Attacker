/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

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
        message.setTokenbindingType(chooser.getConfig().getDefaultTokenBindingType().getTokenBindingTypeValue());
        message.setKeyParameter(chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0).getValue());
        if (chooser.getConfig().getDefaultTokenBindingKeyParameters().get(0) == TokenBindingKeyParameters.ECDSAP256) {
            throw new UnsupportedOperationException("EC TokenBindings are currently not supported!");
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
        SignatureAndHashAlgorithm algorithm = new SignatureAndHashAlgorithm(SignatureAlgorithm.RSA, HashAlgorithm.SHA1);
        message.setSignature(SignatureCalculator.generateSignature(algorithm, chooser, generateToBeSigned()));
        message.setSignatureLength(message.getSignature().getValue().length);
    }

    private byte[] generateToBeSigned() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(new byte[] { message.getTokenbindingType().getValue() });
            stream.write(new byte[] { message.getKeyParameter().getValue() });
            stream.write(TokenCalculator.calculateEKM(chooser.getContext(), 32));
            return stream.toByteArray();
        } catch (IOException ex) {
            throw new PreparationException("Could not generate data to be Signed!", ex);
        }
    }

}
