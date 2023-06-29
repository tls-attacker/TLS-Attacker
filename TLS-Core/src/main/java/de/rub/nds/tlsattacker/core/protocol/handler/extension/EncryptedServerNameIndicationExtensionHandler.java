/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedServerNameIndicationExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedServerNameIndicationExtensionHandler
        extends ExtensionHandler<EncryptedServerNameIndicationExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedServerNameIndicationExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public void adjustTLSExtensionContext(EncryptedServerNameIndicationExtensionMessage message) {
        if (message.getClientEsniInner().getClientNonce() != null) {
            tlsContext.setEsniClientNonce(message.getClientEsniInner().getClientNonce().getValue());
        }
        if (message.getServerNonce() != null) {
            tlsContext.setEsniServerNonce(message.getServerNonce().getValue());
        }
    }
}
