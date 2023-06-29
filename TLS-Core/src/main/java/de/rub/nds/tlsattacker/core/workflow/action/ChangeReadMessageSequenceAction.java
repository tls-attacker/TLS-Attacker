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

@XmlRootElement
public class ChangeReadMessageSequenceAction extends ChangeMessageSequenceAction {

    public ChangeReadMessageSequenceAction() {}

    public ChangeReadMessageSequenceAction(int messageSequence) {
        super(messageSequence);
    }

    @Override
    protected void changeMessageSequence(TlsContext tlsContext) {
        LOGGER.info("Changed read message sequence");
        if (tlsContext.getDtlsFragmentLayer() != null) {
            tlsContext.getDtlsFragmentLayer().setReadHandshakeMessageSequence(messageSequence);
        }
    }
}
