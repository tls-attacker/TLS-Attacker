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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class ChangeWriteMessageSequenceAction extends ChangeMessageSequenceAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChangeWriteMessageSequenceAction() {}

    public ChangeWriteMessageSequenceAction(int messageSequence) {
        super(messageSequence);
    }

    @Override
    protected void changeMessageSequence(TlsContext tlsContext) {
        LOGGER.info("Changed write message sequence");
        if (tlsContext.getDtlsFragmentLayer() != null) {
            tlsContext.getDtlsFragmentLayer().setWriteHandshakeMessageSequence(messageSequence);
        }
    }
}
