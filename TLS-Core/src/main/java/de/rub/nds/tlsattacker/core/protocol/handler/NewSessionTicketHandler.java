/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewSessionTicketMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketHandler extends HandshakeMessageHandler<NewSessionTicketMessage> {

    public NewSessionTicketHandler(TlsContext context) {
        super(context);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public NewSessionTicketMessagePreparator getPreparator(NewSessionTicketMessage message) {
        return new NewSessionTicketMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public NewSessionTicketMessageSerializer getSerializer(NewSessionTicketMessage message) {
        return new NewSessionTicketMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(NewSessionTicketMessage message) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}