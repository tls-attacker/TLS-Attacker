/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class EncryptedServerNameIndicationExtensionHandler extends
        ExtensionHandler<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedServerNameIndicationExtensionHandler(TlsContext context) {
        super(context);
        LOGGER.warn("EncryptedServerNameIndicationExtensionHandler called. - ESNI not implemented yet.");
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer) {
        return null;
    }

    @Override
    public ExtensionPreparator getPreparator(EncryptedServerNameIndicationExtensionMessage message) {
        return new EncryptedServerNameIndicationExtensionPreparator(context.getChooser(), message,
                getSerializer(message));
    }

    @Override
    public ExtensionSerializer getSerializer(EncryptedServerNameIndicationExtensionMessage message) {
        return new EncryptedServerNameIndicationExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(EncryptedServerNameIndicationExtensionMessage message) {
    }

}
