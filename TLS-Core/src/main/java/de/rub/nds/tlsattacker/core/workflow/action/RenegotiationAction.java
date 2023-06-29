/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class RenegotiationAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private boolean resetLastVerifyData = false;

    public RenegotiationAction() {}

    public RenegotiationAction(boolean resetLastVerifyData) {
        this.resetLastVerifyData = resetLastVerifyData;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        LOGGER.info("Resetting MessageDigest");
        tlsContext.getDigest().reset();
        LOGGER.info("Resetting DTLS numbers and cookie");
        tlsContext.setDtlsCookie(null);
        if (tlsContext.getDtlsFragmentLayer() != null) {
            tlsContext.getDtlsFragmentLayer().setReadHandshakeMessageSequence(0);
            tlsContext.getDtlsFragmentLayer().setWriteHandshakeMessageSequence(0);
            tlsContext.getDtlsFragmentLayer().resetFragmentManager(state.getConfig());
        }
        tlsContext.getDtlsReceivedChangeCipherSpecEpochs().clear();
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
