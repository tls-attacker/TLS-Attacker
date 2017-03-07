/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.HelloVerifyRequestPreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.HelloVerifyRequestSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @param <Message>
 * @param <HandshakeMessage>
 */
public class HelloVerifyRequestHandler extends HandshakeMessageHandler<HelloVerifyRequestMessage> {

    public HelloVerifyRequestHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    protected HelloVerifyRequestParser getParser(byte[] message, int pointer) {
        return new HelloVerifyRequestParser(pointer, message);
    }

    @Override
    protected Preparator getPreparator(HelloVerifyRequestMessage message) {
        return new HelloVerifyRequestPreparator(tlsContext, message);
    }

    @Override
    protected Serializer getSerializer(HelloVerifyRequestMessage message) {
        return new HelloVerifyRequestSerializer(message);
    }

    @Override
    protected void adjustTLSContext(HelloVerifyRequestMessage message) {
        tlsContext.setDtlsHandshakeCookie(message.getCookie().getValue());
    }
}
