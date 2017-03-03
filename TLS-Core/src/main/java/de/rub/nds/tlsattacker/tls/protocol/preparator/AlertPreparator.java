/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class AlertPreparator extends ProtocolMessagePreparator<AlertMessage> {

    private final AlertMessage message;

    public AlertPreparator(TlsContext context, AlertMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setLevel(message.getConfig()[0]);
        message.setDescription(message.getConfig()[1]);
    }

}
