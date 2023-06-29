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
public class ChangeWriteEpochAction extends ChangeEpochAction {

    public ChangeWriteEpochAction() {}

    public ChangeWriteEpochAction(int epoch) {
        super(epoch);
    }

    @Override
    protected void changeEpoch(TlsContext tlsContext) {
        LOGGER.info("Changed write epoch");
        if (tlsContext.getRecordLayer() != null) {
            tlsContext.getRecordLayer().setWriteEpoch(epoch);
        }
    }
}
