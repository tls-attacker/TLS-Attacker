/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;
import de.rub.nds.tlsattacker.core.protocol.handler.NewSessionTicketHandler;

/**
 * 
 * @author Timon Wern <timon.wern@rub.de>
 */
@XmlRootElement
public class NewSessionTicketMessage extends ProtocolMessage {

    @ModifiableVariableProperty()
    ModifiableInteger ticketLifetimeHint;

    @ModifiableVariableProperty()
    ModifiableByteArray ticket;
    
    public NewSessionTicketMessage() {
        super();
    }
    
    public NewSessionTicketMessage(Config tlsConfig) {
        super();
    }
    
    public ModifiableInteger getTicketLifetimeHint() {
        return ticketLifetimeHint;
    }
    
    public void setTicketLifetimeHint(ModifiableInteger ticketLifetimeHint) {
        this.ticketLifetimeHint = ticketLifetimeHint;
    }
    
    public void setTicketLifetimeHint(int ticketLifetimeHint) {
        this.ticketLifetimeHint = ModifiableVariableFactory.safelySetValue(this.ticketLifetimeHint, ticketLifetimeHint);
    }
    
    public ModifiableByteArray getTicket() {
        return ticket;
    }
    
    public void setTicket(ModifiableByteArray ticket) {
        this.ticket = ticket;
    }
    
    public void setTicket(byte[] ticket) {
        this.ticket = ModifiableVariableFactory.safelySetValue(this.ticket, ticket);
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("\nNewSessionTicket message:\n  TicketLifeTimeHint: ");
        if (ticketLifetimeHint != null) {
            sb.append(ticketLifetimeHint.getValue());
        } else {
            sb.append("null");
        }
        
        sb.append("\n  Ticket: ");
        if (ticket != null) {
            sb.append(ArrayConverter.bytesToHexString(ticket.getValue())); // TODO remove or trim the complete ticket
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
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new NewSessionTicketHandler(context);
    }
}