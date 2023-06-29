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

@XmlRootElement
public class DeepCopyBuffersAction extends CopyContextFieldAction {

    private State state;

    public DeepCopyBuffersAction() {}

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
        DeepCopyBufferedRecordsAction copyRecords =
                new DeepCopyBufferedRecordsAction(
                        super.getSrcContextAlias(), super.getDstContextAlias());
        DeepCopyBufferedMessagesAction copyMessages =
                new DeepCopyBufferedMessagesAction(
                        super.getSrcContextAlias(), super.getDstContextAlias());

        copyRecords.execute(state);
        copyMessages.execute(state);
        setExecuted(true);
    }
}
