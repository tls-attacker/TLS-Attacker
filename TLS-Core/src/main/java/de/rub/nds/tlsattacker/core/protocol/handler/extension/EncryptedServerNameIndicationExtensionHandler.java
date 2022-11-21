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
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.EncryptedServerNameIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.EncryptedServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EncryptedServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedServerNameIndicationExtensionHandler
    extends ExtensionHandler<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedServerNameIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new EncryptedServerNameIndicationExtensionParser(pointer, message, config);
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
        if (message.getClientEsniInner().getClientNonce() != null) {
            context.setEsniClientNonce(message.getClientEsniInner().getClientNonce().getValue());
        }
        if (message.getServerNonce() != null) {
            context.setEsniServerNonce(message.getServerNonce().getValue());
        }

    }

}
