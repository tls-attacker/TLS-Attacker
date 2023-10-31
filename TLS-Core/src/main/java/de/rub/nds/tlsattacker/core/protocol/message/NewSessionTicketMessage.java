/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.mlong.ModifiableLong;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.handler.NewSessionTicketHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.NewSessionTicketParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.NewSessionTicketPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.NewSessionTicketSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;

@XmlRootElement(name = "NewSessionTicket")
public class NewSessionTicketMessage extends HandshakeMessage<NewSessionTicketMessage> {

    @ModifiableVariableProperty() private ModifiableLong ticketLifetimeHint;

    @HoldsModifiableVariable private final SessionTicket ticket;

    public NewSessionTicketMessage() {
        super(HandshakeMessageType.NEW_SESSION_TICKET);
        ticket = new SessionTicket();
    }

    public NewSessionTicketMessage(Config tlsConfig, boolean includeInDigest) {
        super(HandshakeMessageType.NEW_SESSION_TICKET);
        isIncludeInDigestDefault = includeInDigest;
        ticket = new SessionTicket();
        if (tlsConfig.isAddEarlyDataExtension()) {
            addExtension(new EarlyDataExtensionMessage(true));
        }
    }

    public ModifiableLong getTicketLifetimeHint() {
        return ticketLifetimeHint;
    }

    public void setTicketLifetimeHint(ModifiableLong ticketLifetimeHint) {
        this.ticketLifetimeHint = ticketLifetimeHint;
    }

    public void setTicketLifetimeHint(long ticketLifetimeHint) {
        this.ticketLifetimeHint =
                ModifiableVariableFactory.safelySetValue(
                        this.ticketLifetimeHint, ticketLifetimeHint);
    }

    public SessionTicket getTicket() {
        return ticket;
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
        if (getTicket().getIdentityLength() != null
                && getTicket().getIdentityLength().getValue() != null) {
            sb.append(getTicket().getIdentityLength().getValue());
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
        StringBuilder sb = new StringBuilder();
        sb.append("NEW_SESSION_TICKET");
        if (isRetransmission()) {
            sb.append(" (ret.)");
        }
        return sb.toString();
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
    public NewSessionTicketHandler getHandler(TlsContext tlsContext) {
        return new NewSessionTicketHandler(tlsContext);
    }

    @Override
    public NewSessionTicketParser getParser(TlsContext tlsContext, InputStream stream) {
        return new NewSessionTicketParser(stream, tlsContext);
    }

    @Override
    public NewSessionTicketPreparator getPreparator(TlsContext tlsContext) {
        return new NewSessionTicketPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public NewSessionTicketSerializer getSerializer(TlsContext tlsContext) {
        return new NewSessionTicketSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public String toShortString() {
        return "ST";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 53 * hash + Objects.hashCode(this.ticketLifetimeHint);
        hash = 53 * hash + Objects.hashCode(this.ticket);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final NewSessionTicketMessage other = (NewSessionTicketMessage) obj;
        if (!Objects.equals(this.ticketLifetimeHint, other.ticketLifetimeHint)) {
            return false;
        }
        return Objects.equals(this.ticket, other.ticket);
    }
}
