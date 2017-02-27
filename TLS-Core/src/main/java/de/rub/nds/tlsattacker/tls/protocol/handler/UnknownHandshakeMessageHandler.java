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
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.parser.UnknownHandshakeMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessageHandler extends HandshakeMessageHandler<UnknownHandshakeMessage> {

    public UnknownHandshakeMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
        throw new UnsupportedOperationException("Unsupported yet");
    }

    @Override
    protected void adjustTLSContext(UnknownHandshakeMessage message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    protected UnknownHandshakeMessageParser getParser(byte[] message, int pointer) {
        return new UnknownHandshakeMessageParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(UnknownHandshakeMessage message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    @Override
    protected Serializer getSerializer(UnknownHandshakeMessage message) {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }
}
