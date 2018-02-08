/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.mlong.ModifiableLong;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.NewSessionTicketHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class NewSessionTicketMessage extends HandshakeMessage {

    @ModifiableVariableProperty()
    private ModifiableLong ticketLifetimeHint;

    @ModifiableVariableProperty()
    private ModifiableInteger ticketLength;

    @HoldsModifiableVariable
    private SessionTicket ticket;

    public NewSessionTicketMessage() {
        super(HandshakeMessageType.NEW_SESSION_TICKET);
        ticket = new SessionTicket();
    }

    public NewSessionTicketMessage(boolean includeInDigest) {
        super(HandshakeMessageType.NEW_SESSION_TICKET);
        IS_INCLUDE_IN_DIGEST_DEFAULT = includeInDigest;
        ticket = new SessionTicket();
    }

    public NewSessionTicketMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.NEW_SESSION_TICKET);
        ticket = new SessionTicket();
    }

    public NewSessionTicketMessage(Config tlsConfig, boolean includeInDigest) {
        super(tlsConfig, HandshakeMessageType.NEW_SESSION_TICKET);
        IS_INCLUDE_IN_DIGEST_DEFAULT = includeInDigest;
        ticket = new SessionTicket();
    }

    public ModifiableLong getTicketLifetimeHint() {
        return ticketLifetimeHint;
    }

    public void setTicketLifetimeHint(ModifiableLong ticketLifetimeHint) {
        this.ticketLifetimeHint = ticketLifetimeHint;
    }

    public void setTicketLifetimeHint(long ticketLifetimeHint) {
        this.ticketLifetimeHint = ModifiableVariableFactory.safelySetValue(this.ticketLifetimeHint, ticketLifetimeHint);
    }

    public SessionTicket getTicket() {
        return ticket;
    }

    public void prepareTicket() {
        if (ticket == null) {
            ticket = new SessionTicket();
        }
    }

    public ModifiableInteger getTicketLength() {
        return ticketLength;
    }

    public void setTicketLength(int ticketLength) {
        this.ticketLength = ModifiableVariableFactory.safelySetValue(this.ticketLength, ticketLength);
    }

    public void setTicketLength(ModifiableInteger ticketLength) {
        this.ticketLength = ticketLength;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("NewSessionTicketMessage:");
        sb.append("\n  TicketLifeTimeHint: ");
        if (ticketLifetimeHint != null && ticketLifetimeHint.getValue() != null) {
            sb.append(ticketLifetimeHint.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  TicketLength: ");
        if (ticketLength != null && ticketLength.getValue() != null) {
            sb.append(ticketLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Ticket: ");
        if (ticket != null) {
            sb.append(ticket.toString());
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "NewSessionTicket";
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (ticket != null) {
            holders.add(ticket);
        }
        return holders;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new NewSessionTicketHandler(context);
    }
}
