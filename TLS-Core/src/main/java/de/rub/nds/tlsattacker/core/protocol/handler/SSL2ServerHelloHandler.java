/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.SSL2ServerHelloParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.SSL2ServerHelloPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.SSL2ServerHelloSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ServerHelloHandler extends ProtocolMessageHandler<SSL2ServerHelloMessage> {

    public SSL2ServerHelloHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new SSL2ServerHelloParser(message, pointer, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(SSL2ServerHelloMessage message) {
        return new SSL2ServerHelloPreparator(message, tlsContext.getChooser());
    }

    @Override
    public ProtocolMessageSerializer getSerializer(SSL2ServerHelloMessage message) {
        return new SSL2ServerHelloSerializer(message, tlsContext);
    }

    @Override
    public void adjustTLSContext(SSL2ServerHelloMessage message) {
        // we do nothing since we are not supporting ssl2 and only support the
        // hello messages
    }
}
