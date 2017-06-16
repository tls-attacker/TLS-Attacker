/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloVerifyRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloVerifyRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloVerifyRequestSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    public HelloVerifyRequestParser getParser(byte[] message, int pointer) {
        return new HelloVerifyRequestParser(pointer, message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getLastRecordVersion());
    }

    @Override
    public HelloVerifyRequestPreparator getPreparator(HelloVerifyRequestMessage message) {
        return new HelloVerifyRequestPreparator(new DefaultChooser(tlsContext, tlsContext.getConfig()), message);
    }

    @Override
    public HelloVerifyRequestSerializer getSerializer(HelloVerifyRequestMessage message) {
        return new HelloVerifyRequestSerializer(message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HelloVerifyRequestMessage message) {
        adjustDTLSCookie(message);
    }

    private void adjustDTLSCookie(HelloVerifyRequestMessage message) {
        byte[] dtlsCookie = message.getCookie().getValue();
        tlsContext.setDtlsCookie(dtlsCookie);
        LOGGER.debug("Set DTLS Cookie in Context to " + ArrayConverter.bytesToHexString(dtlsCookie, false));
    }
}
