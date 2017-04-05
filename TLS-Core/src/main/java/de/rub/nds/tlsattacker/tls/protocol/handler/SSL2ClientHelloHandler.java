/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.serializer.SSL2ClientHelloSerializer;
import de.rub.nds.tlsattacker.tls.protocol.preparator.SSL2ClientHelloPreparator;
import de.rub.nds.tlsattacker.tls.protocol.parser.SSL2ClientHelloParser;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SSL2ClientHelloHandler extends ProtocolMessageHandler<SSL2ClientHelloMessage> {

    public SSL2ClientHelloHandler(TlsContext context) {
        super(context);
    }

    @Override
    public SSL2ClientHelloParser getParser(byte[] message, int pointer) {
        return new SSL2ClientHelloParser(message, pointer, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    public SSL2ClientHelloPreparator getPreparator(SSL2ClientHelloMessage message) {
        return new SSL2ClientHelloPreparator(tlsContext, message);
    }

    @Override
    public SSL2ClientHelloSerializer getSerializer(SSL2ClientHelloMessage message) {
        return new SSL2ClientHelloSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(SSL2ClientHelloMessage message) {
        // we do not adjust anything since we dont support the complete ssl2
        // handshake anyways
    }

}
