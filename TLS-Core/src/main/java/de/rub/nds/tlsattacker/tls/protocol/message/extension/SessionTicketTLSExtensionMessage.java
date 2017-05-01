/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message.extension;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class SessionTicketTLSExtensionMessage extends ExtensionMessage {

    private ModifiableByteArray ticket;

    public SessionTicketTLSExtensionMessage() {
        super(ExtensionType.SESSION_TICKET);
    }

    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new SessionTicketTLSExtensionHandler(context);
    }

    public ModifiableByteArray getTicket() {
        return ticket;
    }

    public void setTicket(ModifiableByteArray ticket) {
        this.ticket = ticket;
    }
    
        public void setTicket(byte [] array) {
        this.ticket = ModifiableVariableFactory.safelySetValue(ticket, array);
    }

}
