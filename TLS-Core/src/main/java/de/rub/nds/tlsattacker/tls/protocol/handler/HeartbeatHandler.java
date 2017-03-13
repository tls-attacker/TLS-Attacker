/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handler;

import de.rub.nds.tlsattacker.tls.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;
import de.rub.nds.tlsattacker.tls.protocol.preparator.HeartbeatMessagePreparator;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.protocol.serializer.HeartbeatMessageSerializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Handler for Heartbeat messages: http://tools.ietf.org/html/rfc6520#page-4
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatHandler extends ProtocolMessageHandler<HeartbeatMessage> {

    private static final Logger LOGGER = LogManager.getLogger("HANDLER");
    
    public HeartbeatHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public Parser getParser(byte[] message, int pointer) {
        return new HeartbeatMessageParser(pointer, message, tlsContext.getLastRecordVersion());
    }

    @Override
    public Preparator getPreparator(HeartbeatMessage message) {
        return new HeartbeatMessagePreparator(tlsContext, message);
    }

    @Override
    public Serializer getSerializer(HeartbeatMessage message) {
        return new HeartbeatMessageSerializer(message, tlsContext.getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HeartbeatMessage message) {
        // TODO perhaps something to do here
    }
}
