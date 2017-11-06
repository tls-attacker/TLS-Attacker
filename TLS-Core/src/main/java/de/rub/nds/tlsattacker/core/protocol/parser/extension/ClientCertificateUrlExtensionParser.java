/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;

public class ClientCertificateUrlExtensionParser extends ExtensionParser<ClientCertificateUrlExtensionMessage> {

    public ClientCertificateUrlExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(ClientCertificateUrlExtensionMessage msg) {
        // nothing to parse here, it's an opt-in extension.
    }

    @Override
    protected ClientCertificateUrlExtensionMessage createExtensionMessage() {
        return new ClientCertificateUrlExtensionMessage();
    }

}
