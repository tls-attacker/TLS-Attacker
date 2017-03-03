/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class UnknownHandshakeMessagePreparator extends HandshakeMessagePreparator<UnknownHandshakeMessage> {

    private final UnknownHandshakeMessage message;

    public UnknownHandshakeMessagePreparator(TlsContext context, UnknownHandshakeMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setData(message.getDataConfig());
    }

}
