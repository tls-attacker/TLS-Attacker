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
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
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

    @ModifiableVariableProperty
    private ModifiableByteArray ticket;

    /**
     * Constructor
     */
    public SessionTicketTLSExtensionMessage() {
        super(ExtensionType.SESSION_TICKET);
    }

    /**
     * Returns a new SessionTicketTLSExtensionHandler
     *
     * @param context
     *            A TLSContext
     * @return A new SessionTicketTLSExtensionHandler
     */
    @Override
    public ExtensionHandler getHandler(TlsContext context) {
        return new SessionTicketTLSExtensionHandler(context);
    }

    /**
     * Returns the saved SessionTicket
     *
     * @return
     */
    public ModifiableByteArray getTicket() {
        return ticket;
    }

    /**
     * Sets the SessionTicket
     *
     * @param ticket
     */
    public void setTicket(ModifiableByteArray ticket) {
        this.ticket = ticket;
    }

    /**
     * Sets the SessionTicket
     *
     * @param array
     */
    public void setTicket(byte[] array) {
        this.ticket = ModifiableVariableFactory.safelySetValue(ticket, array);
    }

}
