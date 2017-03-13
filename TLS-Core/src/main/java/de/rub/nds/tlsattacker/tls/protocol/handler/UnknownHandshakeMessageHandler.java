/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.parser.UnknownHandshakeMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.UnknownHandshakeMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.UnknownHandshakeMessageSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageHandler extends HandshakeMessageHandler<UnknownHandshakeMessage> {

    public UnknownHandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected void adjustTLSContext(UnknownHandshakeMessage message) {
        // nothing to adjust here
    }

    @Override
    public UnknownHandshakeMessageParser getParser(byte[] message, int pointer) {
        return new UnknownHandshakeMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(UnknownHandshakeMessage message) {
        return new UnknownHandshakeMessagePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(UnknownHandshakeMessage message) {
        return new UnknownHandshakeMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }
}
