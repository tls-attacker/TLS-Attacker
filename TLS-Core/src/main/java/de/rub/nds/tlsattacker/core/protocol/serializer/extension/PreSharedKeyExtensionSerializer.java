/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;

/**
 * RFC draft-ietf-tls-tls13-21
 *
 * @author Marcel Maehren <marcel.maehren@rub.de>
 */
public class PreSharedKeyExtensionSerializer extends ExtensionSerializer<PreSharedKeyExtensionMessage> {

    private final PreSharedKeyExtensionMessage msg;
    
    public PreSharedKeyExtensionSerializer(PreSharedKeyExtensionMessage message) {
        super(message);
        msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        //TODO
        LOGGER.debug("Serializing PreSharedKeyExtensionMessage");
        return getAlreadySerialized();
    }
    
    

}
