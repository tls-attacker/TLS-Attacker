/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.dtls.FragmentManager;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class RenegotiationAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean resetLastVerifyData = false;

    public RenegotiationAction() {
    }

    public RenegotiationAction(boolean resetLastVerifyData) {
        this.resetLastVerifyData = resetLastVerifyData;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        LOGGER.info("Resetting MessageDigest");
        tlsContext.getDigest().reset();
        LOGGER.info("Resetting DTLS numbers and cookie");
        tlsContext.setDtlsCookie(null);
        tlsContext.setDtlsReadHandshakeMessageSequence(0);
        tlsContext.setDtlsWriteHandshakeMessageSequence(0);
        tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
        tlsContext.setDtlsFragmentManager(new FragmentManager(state.getConfig()));
        tlsContext.getDtlsReceivedHandshakeMessageSequences().clear();
        if (resetLastVerifyData) {
            LOGGER.info("Resetting SecureRenegotiation");
            tlsContext.setLastClientVerifyData(null);
            tlsContext.setLastServerVerifyData(null);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
