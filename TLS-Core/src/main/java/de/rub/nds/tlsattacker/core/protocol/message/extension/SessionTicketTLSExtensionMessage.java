/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

/**
 * This extension is defined in RFC4507
 */
public class SessionTicketTLSExtensionMessage extends ExtensionMessage<SessionTicketTLSExtensionMessage> {

    @ModifiableVariableProperty
    private ModifiableByteArray ticket;

    /**
     * Constructor
     */
    public SessionTicketTLSExtensionMessage() {
        super(ExtensionType.SESSION_TICKET);
    }

    public SessionTicketTLSExtensionMessage(Config config) {
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
     *               the Raw ticket bytes
     */
    public void setTicket(ModifiableByteArray ticket) {
        this.ticket = ticket;
    }

    /**
     * Sets the SessionTicket
     *
     * @param array
     *              the Raw ticket bytes
     */
    public void setTicket(byte[] array) {
        this.ticket = ModifiableVariableFactory.safelySetValue(ticket, array);
    }

    @Override
    public SessionTicketTLSExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SessionTicketTLSExtensionParser(stream, tlsContext.getConfig());
    }

    @Override
    public SessionTicketTLSExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionPreparator(tlsContext.getChooser(), this, getSerializer(tlsContext));
    }

    @Override
    public SessionTicketTLSExtensionSerializer getSerializer(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionSerializer(this);
    }

    @Override
    public SessionTicketTLSExtensionHandler getHandler(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionHandler(tlsContext);

    }
}
