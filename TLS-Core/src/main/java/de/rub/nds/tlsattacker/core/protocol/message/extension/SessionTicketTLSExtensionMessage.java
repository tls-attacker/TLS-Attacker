/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;

/**
 * This extension is defined in RFC4507
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
     * Returns the saved SessionTicket
     *
     * @return the Raw ticket
     */
    public ModifiableByteArray getTicket() {
        return ticket;
    }

    /**
     * Sets the SessionTicket
     *
     * @param ticket
     *            the Raw ticket bytes
     */
    public void setTicket(ModifiableByteArray ticket) {
        this.ticket = ticket;
    }

    /**
     * Sets the SessionTicket
     *
     * @param array
     *            the Raw ticket bytes
     */
    public void setTicket(byte[] array) {
        this.ticket = ModifiableVariableFactory.safelySetValue(ticket, array);
    }

}
