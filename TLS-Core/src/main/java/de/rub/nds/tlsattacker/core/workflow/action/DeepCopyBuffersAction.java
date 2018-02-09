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

public class DeepCopyBuffersAction extends CopyContextFieldAction {

    private State state;

    public DeepCopyBuffersAction() {

    }

    public DeepCopyBuffersAction(String srcConnectionAlias, String dstConnectionAlias) {
        super(srcConnectionAlias, dstConnectionAlias);
    }

    @Override
    public void execute(State state) {
        this.state = state;
        super.execute(state);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    protected void copyField(TlsContext srcContext, TlsContext dstContext) {
        DeepCopyBufferedRecordsAction copyRecords = new DeepCopyBufferedRecordsAction(super.getSrcContextAlias(),
                super.getDstContextAlias());
        DeepCopyBufferedMessagesAction copyMessages = new DeepCopyBufferedMessagesAction(super.getSrcContextAlias(),
                super.getDstContextAlias());

        copyRecords.execute(state);
        copyMessages.execute(state);
    }

}
