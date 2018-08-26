/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import static de.rub.nds.tlsattacker.core.workflow.action.TlsAction.LOGGER;
import java.io.IOException;

/**
 * Check if a protocol message of given type was received.
 * 
 * Checks all protocol message that were received during workflow execution so
 * far. Result is stored in "found" field. Prints "Found Type.name (Type.value)"
 * for the first message found and quits. Prints nothing if no message of given
 * type was received.
 */
public class FindReceivedProtocolMessageAction extends ConnectionBoundAction {

    private ProtocolMessageType protocolMessageType;
    private Boolean found = false;

    public FindReceivedProtocolMessageAction() {
    }

    public FindReceivedProtocolMessageAction(ProtocolMessageType protocolMessageType) {
        this.protocolMessageType = protocolMessageType;
    }

    public FindReceivedProtocolMessageAction(String alias, ProtocolMessageType protocolMessageType) {
        super(alias);
        this.protocolMessageType = protocolMessageType;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        TlsContext ctx = state.getTlsContext(getConnectionAlias());
        found = WorkflowTraceUtil.didReceiveMessage(protocolMessageType, state.getWorkflowTrace());
        if (found) {
            LOGGER.log(LogLevel.DIRECT, "Found " + protocolMessageType.name() + " (" + protocolMessageType.getValue()
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
