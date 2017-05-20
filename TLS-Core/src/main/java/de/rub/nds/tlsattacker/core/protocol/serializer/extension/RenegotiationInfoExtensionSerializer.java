/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionSerializer extends ExtensionSerializer<RenegotiationInfoExtensionMessage> {

    private final RenegotiationInfoExtensionMessage message;

    public RenegotiationInfoExtensionSerializer(RenegotiationInfoExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getRenegotiationInfo().getValue());
        LOGGER.debug("Serialized RenegotiationInfo extension with info of length "
                + message.getRenegotiationInfo().getValue().length);
        return getAlreadySerialized();
    }

}
