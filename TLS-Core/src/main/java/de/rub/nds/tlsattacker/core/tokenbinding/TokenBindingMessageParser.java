/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class TokenBindingMessageParser extends ProtocolMessageParser<TokenBindingMessage> {

    private final TokenBindingKeyParameters keyParameter;

    public TokenBindingMessageParser(int pointer, byte[] array, ProtocolVersion version, TokenBindingKeyParameters keyParameter) {
        super(pointer, array, version);
        this.keyParameter = keyParameter;
    }

    @Override
    protected TokenBindingMessage parseMessageContent() {
        TokenBindingMessage message = new TokenBindingMessage();
        message.setTokenbindingType(parseByteField(TokenBindingLength.BINDING_TYPE));
        message.setKeyLength(TokenBindingLength.KEY);
        if (keyParameter == TokenBindingKeyParameters.ECDSAP256) {
            message.setPointLength(parseIntField(TokenBindingLength.POINT));
            message.setPoint(parseByteArrayField(message.getPointLength().getValue()));
        } else {
            message.setModulusLength(parseIntField(TokenBindingLength.MODULUS));
            message.setModulus(parseByteArrayField(message.getModulusLength().getValue()));
            message.setPublicExponentLength(parseIntField(TokenBindingLength.PUBLIC_EXPONENT));
            message.setPublicExponent(parseByteArrayField(message.getPublicExponentLength().getValue()));
        }
        message.setSignatureLength(parseIntField(TokenBindingLength.SIGNATURE));
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        message.setExtensionLength(parseIntField(TokenBindingLength.EXTENSIONS));
        message.setExtensionBytes(parseByteArrayField(message.getExtensionLength().getValue()));
        return message;
    }

}
