/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import static de.rub.nds.tlsattacker.core.protocol.serializer.Serializer.LOGGER;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessageSerializer extends ProtocolMessageSerializer<NewSessionTicketMessage> {

    private final NewSessionTicketMessage msg;
    
    /**
     * Constructor for the NewSessionTicketSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public NewSessionTicketMessageSerializer(NewSessionTicketMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeProtocolMessageContent() {
        LOGGER.debug("Serializing NewSessionTicketMessage");
        writeTicketLifetimeHint(msg);
        writeTicket(msg);
        return getAlreadySerialized();
    }

    private void writeTicketLifetimeHint(NewSessionTicketMessage msg) {
        appendInt(msg.getTicketLifetimeHint().getValue(), 4); // TODO Implement constant(?) Check for unsigned
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint().getValue());
    }

    private void writeTicket(NewSessionTicketMessage msg) {
        appendBytes(msg.getTicket().getValue());
        LOGGER.debug("Ticket: " + ArrayConverter.bytesToHexString(msg.getTicket().getValue())); // TODO remove or trim the complete ticket
    }
}