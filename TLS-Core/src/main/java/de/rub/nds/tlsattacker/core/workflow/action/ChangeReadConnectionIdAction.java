/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "ChangeReadConnectionId")
public class ChangeReadConnectionIdAction extends ChangeConnectionIdAction {

    public ChangeReadConnectionIdAction() {}

    public ChangeReadConnectionIdAction(byte[] connectionId) {
        super(connectionId);
    }

    public ChangeReadConnectionIdAction(byte[] connectionId, int index) {
        super(connectionId, index);
    }

    @Override
    protected void changeConnectionId(TlsContext tlsContext) {
        if (index != null) {
            tlsContext.setReadConnectionId(connectionId, index);
        } else {
            tlsContext.setReadConnectionId(connectionId);
        }
        LOGGER.info("Changed read connection id");
    }
}
