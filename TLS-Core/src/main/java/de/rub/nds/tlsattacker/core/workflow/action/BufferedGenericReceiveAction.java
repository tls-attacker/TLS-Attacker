/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BufferedGenericReceiveAction extends GenericReceiveAction {

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
        System.out.println("record bufferedGener...: " + records.size());
    }

}
