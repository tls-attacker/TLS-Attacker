/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.intToBytes;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.protocol.message.extension.TokenBindingExtensionMessage;
import java.util.ArrayList;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class TokenBindingExtensionSerializer extends ExtensionSerializer<TokenBindingExtensionMessage> {

    private final TokenBindingExtensionMessage message;

    public TokenBindingExtensionSerializer(TokenBindingExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(new byte[] { message.getMajor().getByteValue() });
        appendBytes(new byte[] { message.getMinor().getByteValue() });
        appendByte((byte) message.getParameterListLength());
        for (TokenBindingKeyParameters kp : message.getTokenbindingParameters()) {
            appendByte(kp.getKeyParameterValue());
        }
        LOGGER.debug("Serialized the token binding extension.");
        return getAlreadySerialized();
    }
}
