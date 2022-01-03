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
import de.rub.nds.tlsattacker.core.constants.AuthzDataFormat;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientAuthzExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ClientAuthzExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientAuthzExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ClientAuthzExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ClientAuthzExtensionHandler extends ExtensionHandler<ClientAuthzExtensionMessage> {

    public ClientAuthzExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ClientAuthzExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new ClientAuthzExtensionParser(pointer, message, config);
    }

    @Override
    public ClientAuthzExtensionPreparator getPreparator(ClientAuthzExtensionMessage message) {
        return new ClientAuthzExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public ClientAuthzExtensionSerializer getSerializer(ClientAuthzExtensionMessage message) {
        return new ClientAuthzExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(ClientAuthzExtensionMessage message) {
        context.setClientAuthzDataFormatList(AuthzDataFormat.byteArrayToList(message.getAuthzFormatList().getValue()));
    }

}
