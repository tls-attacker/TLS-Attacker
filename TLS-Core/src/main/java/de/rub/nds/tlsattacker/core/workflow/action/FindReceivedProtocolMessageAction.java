/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Check if a protocol message of given type was received.
 *
 * <p>Checks all protocol message that were received during workflow execution so far. Result is
 * stored in "found" field. Prints "Found Type.name (Type.value)" for the first message found and
 * quits. Prints nothing if no message of given type was received.
 */
@XmlRootElement
public class FindReceivedProtocolMessageAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private ProtocolMessageType protocolMessageType;
    private Boolean found = false;

    public FindReceivedProtocolMessageAction() {}

    public FindReceivedProtocolMessageAction(ProtocolMessageType protocolMessageType) {
        this.protocolMessageType = protocolMessageType;
    }

    public FindReceivedProtocolMessageAction(
            String alias, ProtocolMessageType protocolMessageType) {
        super(alias);
        this.protocolMessageType = protocolMessageType;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext ctx = state.getContext(getConnectionAlias()).getTlsContext();
        found = WorkflowTraceUtil.didReceiveMessage(protocolMessageType, state.getWorkflowTrace());
        if (found) {
            LOGGER.info(
                    "Found "
                            + protocolMessageType.name()
                            + " ("
                            + protocolMessageType.getValue()
                            + ")");
        }
        setExecuted(Boolean.TRUE);
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    public void setProtocolMessageType(ProtocolMessageType protocolMessageType) {
        this.protocolMessageType = protocolMessageType;
    }

    public Boolean isFound() {
        return found;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }
}
