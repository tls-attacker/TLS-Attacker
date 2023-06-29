/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.SessionTicketTLSExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.SessionTicketTLSExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.SessionTicketTLSExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.SessionTicketTLSExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.SessionTicket;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This extension is defined in RFC4507 */
@XmlRootElement(name = "SessionTicketTLSExtension")
public class SessionTicketTLSExtensionMessage
        extends ExtensionMessage<SessionTicketTLSExtensionMessage> {

    @HoldsModifiableVariable private SessionTicket sessionTicket;

    /** Constructor */
    public SessionTicketTLSExtensionMessage() {
        super(ExtensionType.SESSION_TICKET);
        sessionTicket = new SessionTicket();
    }

    public SessionTicket getSessionTicket() {
        return sessionTicket;
    }

    public void setSessionTicket(SessionTicket sessionTicket) {
        this.sessionTicket = sessionTicket;
    }

    @Override
    public SessionTicketTLSExtensionParser getParser(TlsContext tlsContext, InputStream stream) {
        return new SessionTicketTLSExtensionParser(stream, tlsContext.getConfig(), tlsContext);
    }

    @Override
    public SessionTicketTLSExtensionPreparator getPreparator(TlsContext tlsContext) {
        return new SessionTicketTLSExtensionPreparator(tlsContext.getChooser(), this);
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
