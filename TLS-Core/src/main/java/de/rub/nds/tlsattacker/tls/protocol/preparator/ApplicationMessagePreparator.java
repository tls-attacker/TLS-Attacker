/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ApplicationMessagePreparator extends ProtocolMessagePreparator<ApplicationMessage> {

    private final ApplicationMessage message;

    public ApplicationMessagePreparator(TlsContext context, ApplicationMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setData(context.getConfig().getDefaultApplicationMessageData().getBytes());
    }

}
