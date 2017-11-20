/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;

public class ClientCertificateUrlExtensionSerializer extends ExtensionSerializer<ClientCertificateUrlExtensionMessage> {

    public ClientCertificateUrlExtensionSerializer(ClientCertificateUrlExtensionMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeExtensionContent() {
        return getAlreadySerialized();
    }

}
