/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
public class NewSessionTicketMessagePreparator extends ProtocolMessagePreparator<NewSessionTicketMessage> {

    private final NewSessionTicketMessage msg;

    public NewSessionTicketMessagePreparator(Chooser chooser, NewSessionTicketMessage message) {
        super(chooser, message);
        this.msg = message;
    }
    
    /**
     * The NewSessionTicket handshake message has been assigned the number 4
     * and its definition is given at the end of this section. The
     * ticket_lifetime_hint field contains a hint from the server about how
     * long the ticket should be stored.  The value indicates the lifetime
     * in seconds as a 32-bit unsigned integer in network byte order
     * relative to when the ticket is received.  A value of zero is reserved
     * to indicate that the lifetime of the ticket is unspecified.  A client
     * SHOULD delete the ticket and associated state when the time expires.
     * It MAY delete the ticket earlier based on local policy.  A server MAY
     * treat a ticket as valid for a shorter or longer period of time than
     * what is stated in the ticket_lifetime_hint.
     */
    private int generateTicketLifetimeHint() {
        return 0; // TODO Set specific value for lifetime through chooser(?)
    }
    
    private byte[] generateTicket() {
        byte[] ticket = chooser.getSessionTicketTLS();
        return ticket;
    }
    
    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing NewSessionTicketMessage");
        prepareTicketLifetimeHint(msg);
        prepareTicket(msg);
    }

    private void prepareTicketLifetimeHint(NewSessionTicketMessage msg) {
        msg.setTicketLifetimeHint(generateTicketLifetimeHint());
        LOGGER.debug("TicketLifetimeHint: " + msg.getTicketLifetimeHint());
    }

    private void prepareTicket(NewSessionTicketMessage msg) {
        msg.setTicket(generateTicket());
        LOGGER.debug("Ticket: " + ArrayConverter.bytesToHexString(msg.getTicket().getValue())); // TODO remove or trim the complete ticket
    }
}