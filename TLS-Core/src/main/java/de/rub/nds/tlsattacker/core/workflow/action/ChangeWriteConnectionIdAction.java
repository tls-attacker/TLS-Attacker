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

@XmlRootElement(name = "ChangeWriteConnectionId")
public class ChangeWriteConnectionIdAction extends ChangeConnectionIdAction {

    public ChangeWriteConnectionIdAction() {}

    public ChangeWriteConnectionIdAction(byte[] connectionId) {
        super(connectionId);
    }

    public ChangeWriteConnectionIdAction(byte[] connectionId, int index) {
        super(connectionId, index);
    }

    @Override
    protected void changeConnectionId(TlsContext tlsContext) {
        if (index != null) {
            tlsContext.setWriteConnectionId(connectionId, index);
        } else {
            tlsContext.setWriteConnectionId(connectionId);
        }
        LOGGER.info("Changed write connection id");
    }
}
