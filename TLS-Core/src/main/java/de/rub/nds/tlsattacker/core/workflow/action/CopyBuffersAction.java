/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "CopyBuffers")
public class CopyBuffersAction extends CopyContextFieldAction {

    public CopyBuffersAction() {}

    public CopyBuffersAction(String srcConnectionAlias, String dstConnectionAlias) {
        super(srcConnectionAlias, dstConnectionAlias);
    }

    @Override
    protected void copyField(TlsContext src, TlsContext dst) {
        dst.setRecordBuffer(src.getRecordBuffer());
        dst.setMessageBuffer(src.getMessageBuffer());
        setExecuted(true);
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
    public String toString() {
        return "CopyBuffersAction: " + getSrcContextAlias() + " -> " + getDstContextAlias();
    }
}
