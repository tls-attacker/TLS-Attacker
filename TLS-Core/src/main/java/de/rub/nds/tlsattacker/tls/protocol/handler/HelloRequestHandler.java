/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.HelloRequestPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.HelloRequestSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class HelloRequestHandler extends HandshakeMessageHandler<HelloRequestMessage> {

    public HelloRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected Parser getParser(byte[] message, int pointer) {
        return new HelloRequestParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(HelloRequestMessage message) {
        return new HelloRequestPreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(HelloRequestMessage message) {
        return new HelloRequestSerializer(message);
    }

    @Override
    protected void adjustTLSContext(HelloRequestMessage message) {
        // we adjust nothing
    }
}
