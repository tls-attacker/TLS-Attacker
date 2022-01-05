/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
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
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        tlsContext.getMessageBuffer().addAll(messages);
        tlsContext.getRecordBuffer().addAll(records);
        LOGGER.debug("New message buffer size: " + messages.size());
        LOGGER.debug("New record buffer size: " + records.size());
    }

}
