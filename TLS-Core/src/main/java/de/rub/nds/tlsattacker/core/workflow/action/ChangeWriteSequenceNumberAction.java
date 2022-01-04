/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ChangeWriteSequenceNumberAction extends ChangeSequenceNumberAction {

    public ChangeWriteSequenceNumberAction() {
    }

    public ChangeWriteSequenceNumberAction(long sequenceNumber) {
        super(sequenceNumber);
    }

    @Override
    protected void changeSequenceNumber(TlsContext tlsContext) {
        LOGGER.info("Changed write sequence number of current cipher");
        tlsContext.setWriteSequenceNumber(tlsContext.getWriteEpoch(), sequenceNumber);
    }

}
