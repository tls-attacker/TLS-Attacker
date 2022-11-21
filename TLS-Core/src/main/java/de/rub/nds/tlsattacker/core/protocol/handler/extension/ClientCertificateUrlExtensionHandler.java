/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientCertificateUrlExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientCertificateUrlExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientCertificateUrlExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientCertificateUrlExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ClientCertificateUrlExtensionHandler extends ExtensionHandler<ClientCertificateUrlExtensionMessage> {

    public ClientCertificateUrlExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ClientCertificateUrlExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new ClientCertificateUrlExtensionParser(pointer, message, config);
    }

    @Override
    public ClientCertificateUrlExtensionPreparator getPreparator(ClientCertificateUrlExtensionMessage message) {
        return new ClientCertificateUrlExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ClientCertificateUrlExtensionSerializer getSerializer(ClientCertificateUrlExtensionMessage message) {
        return new ClientCertificateUrlExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(ClientCertificateUrlExtensionMessage message) {
    }

}
