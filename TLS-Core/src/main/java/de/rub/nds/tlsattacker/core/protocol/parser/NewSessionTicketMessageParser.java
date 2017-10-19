/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessageParser extends ProtocolMessageParser<NewSessionTicketMessage> {

    /**
     * Constructor for the Parser class
     *
     * @param startposition
     *            Position in the array where the ProtocolMessageParser is
     *            supposed to start parsing
     * @param array
     *            The byte[] which the ProtocolMessageParser is supposed to
     *            parse
     * @param version
     *            Version of the Protocol
     */
    public NewSessionTicketMessageParser(int startposition, byte[] array, ProtocolVersion version) {
        super(startposition, array, version);
    }

    @Override
    public NewSessionTicketMessage parseMessageContent() {
        LOGGER.debug("Parsing NewSessionTicketMessage");
        NewSessionTicketMessage msg = new NewSessionTicketMessage();
        parseTicketLifeTimeHint(msg);
        parseTicket(msg);
        return msg;
    }

    /**
     * Reads the next bytes as the TicketLifeTimeHint and writes it in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseTicketLifeTimeHint(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(parseIntField(4)); // TODO Implement constant(?) Check for unsigned
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint().getValue());
    }
    
    /**
     * Reads the next bytes as the Ticket and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseTicket(NewSessionTicketMessage msg) {
        msg.setTicket(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Ticket: " + ArrayConverter.bytesToHexString(msg.getTicket().getValue())); // TODO remove or trim the complete ticket
    }
}