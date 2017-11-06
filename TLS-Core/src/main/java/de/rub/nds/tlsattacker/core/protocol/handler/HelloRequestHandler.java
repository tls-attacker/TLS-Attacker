/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRequestSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class HelloRequestHandler extends HandshakeMessageHandler<HelloRequestMessage> {

    public HelloRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HelloRequestParser getParser(byte[] message, int pointer) {
        return new HelloRequestParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public HelloRequestPreparator getPreparator(HelloRequestMessage message) {
        return new HelloRequestPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public HelloRequestSerializer getSerializer(HelloRequestMessage message) {
        return new HelloRequestSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(HelloRequestMessage message) {
        // we adjust nothing
    }
}
