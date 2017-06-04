/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRetryRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRetryRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRetryRequestSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class HelloRetryRequestHandler extends HandshakeMessageHandler<HelloRetryRequestMessage> {

    public HelloRetryRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HelloRetryRequestParser getParser(byte[] message, int pointer) {
        return new HelloRetryRequestParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public HelloRetryRequestPreparator getPreparator(HelloRetryRequestMessage message) {
        return new HelloRetryRequestPreparator(tlsContext, message);
    }

    @Override
    public HelloRetryRequestSerializer getSerializer(HelloRetryRequestMessage message) {
        return new HelloRetryRequestSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HelloRetryRequestMessage message) {
        adjustProtocolVersion(message);
        adjustLastRecordVersion(message);
        if (message.getExtensions() != null) {
            for (ExtensionMessage extension : message.getExtensions()) {
                extension.getHandler(tlsContext).adjustTLSContext(extension);
            }
        }
    }

    private void adjustProtocolVersion(HelloRetryRequestMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        tlsContext.setSelectedProtocolVersion(version);
        LOGGER.debug("Set SelectedProtocolVersion in Context to " + version.name());
    }

    private void adjustLastRecordVersion(HelloRetryRequestMessage message) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(message.getProtocolVersion().getValue());
        tlsContext.setLastRecordVersion(version);
        LOGGER.debug("Set LastRecordVersion in Context to " + version.name());
    }

}
