/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HeartbeatMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HeartbeatMessageSerializer;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;

/**
 * Handler for Heartbeat messages: http://tools.ietf.org/html/rfc6520#page-4
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatHandler extends ProtocolMessageHandler<HeartbeatMessage> {

    public HeartbeatHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public HeartbeatMessageParser getParser(byte[] message, int pointer) {
        return new HeartbeatMessageParser(pointer, message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getLastRecordVersion());
    }

    @Override
    public HeartbeatMessagePreparator getPreparator(HeartbeatMessage message) {
        return new HeartbeatMessagePreparator(new DefaultChooser(tlsContext, tlsContext.getConfig()), message);
    }

    @Override
    public HeartbeatMessageSerializer getSerializer(HeartbeatMessage message) {
        return new HeartbeatMessageSerializer(message,
                new DefaultChooser(tlsContext, tlsContext.getConfig()).getSelectedProtocolVersion());
    }

    @Override
    protected void adjustTLSContext(HeartbeatMessage message) {
        // TODO perhaps something to do here
    }
}
