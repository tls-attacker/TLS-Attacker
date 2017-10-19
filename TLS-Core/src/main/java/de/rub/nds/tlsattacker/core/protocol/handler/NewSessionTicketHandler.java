/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.parser.NewSessionTicketMessageParser;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ProtocolMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewSessionTicketMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ProtocolMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketHandler extends ProtocolMessageHandler<NewSessionTicketMessage> {

    public NewSessionTicketHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public ProtocolMessageParser getParser(byte[] message, int pointer) {
        return new NewSessionTicketMessageParser(pointer, message, tlsContext.getChooser().getLastRecordVersion());
    }

    @Override
    public ProtocolMessagePreparator getPreparator(NewSessionTicketMessage message) {
        return new NewSessionTicketMessagePreparator(tlsContext.getChooser(), message);
    }

    @Override
    public ProtocolMessageSerializer getSerializer(NewSessionTicketMessage message) {
        return new NewSessionTicketMessageSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(NewSessionTicketMessage message) {
        // TODO search other handler for references what to do here
    }
}