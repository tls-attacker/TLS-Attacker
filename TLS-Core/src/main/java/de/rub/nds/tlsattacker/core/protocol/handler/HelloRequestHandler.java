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
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class HelloRequestHandler extends HandshakeMessageHandler<HelloRequestMessage> {

    public HelloRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HelloRequestParser getParser(byte[] message, int pointer) {
        return new HelloRequestParser(pointer, message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getLastRecordVersion());
    }

    @Override
    public HelloRequestPreparator getPreparator(HelloRequestMessage message) {
        return new HelloRequestPreparator(new DefaultChooser(tlsContext, tlsContext.getConfig()), message);
    }

    @Override
    public HelloRequestSerializer getSerializer(HelloRequestMessage message) {
        return new HelloRequestSerializer(message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HelloRequestMessage message) {
        // we adjust nothing
    }
}
