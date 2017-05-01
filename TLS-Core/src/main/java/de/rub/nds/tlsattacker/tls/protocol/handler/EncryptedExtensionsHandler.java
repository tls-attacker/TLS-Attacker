/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.EncryptedExtensionsParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.EncryptedExtensionsPreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class EncryptedExtensionsHandler extends HandshakeMessageHandler<EncryptedExtensionsMessage> {

    public EncryptedExtensionsHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public EncryptedExtensionsParser getParser(byte[] message, int pointer) {
        return new EncryptedExtensionsParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public EncryptedExtensionsPreparator getPreparator(EncryptedExtensionsMessage message) {
        return new EncryptedExtensionsPreparator(tlsContext, message);
    }

    @Override
    public EncryptedExtensionsSerializer getSerializer(EncryptedExtensionsMessage message) {
        return new EncryptedExtensionsSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(EncryptedExtensionsMessage message) {
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                extension.getHandler(tlsContext).adjustTLSContext(extension);
            }
        }
    }
    
}