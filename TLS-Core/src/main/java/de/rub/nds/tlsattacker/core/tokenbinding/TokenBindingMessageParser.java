/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageParser;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TokenBindingMessageParser extends ProtocolMessageParser<TokenBindingMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public TokenBindingMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(TokenBindingMessage message) {
        message.setTokenbindingsLength(parseIntField(TokenBindingLength.TOKENBINDINGS));
        LOGGER.debug("TokenbindingLength: {}", message.getTokenbindingsLength().getValue());
        message.setTokenbindingType(parseByteField(TokenBindingLength.BINDING_TYPE));
        LOGGER.debug("TokenBindingType: {}", message.getTokenbindingType().getValue());

        message.setKeyParameter(parseByteField(TokenBindingLength.KEY_PARAMETER));
        LOGGER.debug("KeyParameter: {}", message.getKeyParameter().getValue());

        TokenBindingKeyParameters keyParameter =
                TokenBindingKeyParameters.getTokenBindingKeyParameter(
                        message.getKeyParameter().getValue());
        message.setKeyLength(parseIntField(TokenBindingLength.KEY));
        LOGGER.debug("KeyLength: {}", message.getKeyLength().getValue());

        if (keyParameter.equals(TokenBindingKeyParameters.ECDSAP256)) {
            message.setPointLength(parseIntField(TokenBindingLength.POINT));
            LOGGER.debug("PointLength: {}", message.getPointLength().getValue());

            message.setPoint(parseByteArrayField(message.getPointLength().getValue()));
            LOGGER.debug("Point: {}", message.getPoint().getValue());

        } else {
            message.setModulusLength(parseIntField(TokenBindingLength.MODULUS));
            message.setModulus(parseByteArrayField(message.getModulusLength().getValue()));
            message.setPublicExponentLength(parseIntField(TokenBindingLength.PUBLIC_EXPONENT));
            message.setPublicExponent(
                    parseByteArrayField(message.getPublicExponentLength().getValue()));
        }
        message.setSignatureLength(parseIntField(TokenBindingLength.SIGNATURE));
        LOGGER.debug("SignatureLength: {}", message.getSignatureLength().getValue());

        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", message.getSignature().getValue());

        message.setExtensionLength(parseIntField(TokenBindingLength.EXTENSIONS));
        LOGGER.debug("ExtensionLength: {}", message.getExtensionLength().getValue());

        message.setExtensionBytes(parseByteArrayField(message.getExtensionLength().getValue()));
        LOGGER.debug("Extensions: {}", message.getExtensionBytes().getValue());
    }
}
