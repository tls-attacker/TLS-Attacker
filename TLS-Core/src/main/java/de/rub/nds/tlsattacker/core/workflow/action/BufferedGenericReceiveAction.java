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
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "BufferedGenericReceive")
public class BufferedGenericReceiveAction extends GenericReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public BufferedGenericReceiveAction() {
        super();
    }

    public BufferedGenericReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) {
        super.execute(state);
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();
        tlsContext.getMessageBuffer().addAll(getReceivedMessages());
        tlsContext.getRecordBuffer().addAll(getReceivedRecords());
        LOGGER.debug("New message buffer size: {}", tlsContext.getMessageBuffer().size());
        LOGGER.debug("New record buffer size: {}", tlsContext.getRecordBuffer().size());
    }
}
