/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * 
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ForwardAction extends MessageAction {

    private String receiveFromAlias = null;
    private String forwardToAlias = null;
    ReceiveAction recvAction = null;
    SendAction sendAction = null;

    public ForwardAction() {
        super();
    }

    public ForwardAction(ProtocolMessage... messages) {
        super(messages);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        if (receiveFromAlias == null) {
            throw new WorkflowExecutionException("Can't execute ForwardAction with empty receiveFromAlias");
        }
        if (forwardToAlias == null) {
            throw new WorkflowExecutionException("Can't execute ForwardAction with empty forwardToAlias");
        }
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        recvAction = new ReceiveAction(messages);
        recvAction.setContextAlias(receiveFromAlias);
        recvAction.execute(state);

        List<ProtocolMessage> receivedMessages = recvAction.getReceivedMessages();
        // Apply the action to the forward destination's context
        for (ProtocolMessage msg : receivedMessages) {
            LOGGER.info("Applying " + msg.toCompactString() + "to forward context " + forwardToAlias);
            ProtocolMessageHandler h = msg.getHandler(state.getTlsContext(forwardToAlias));
            h.adjustTLSContext(msg);
        }

        sendAction = new SendAction(receivedMessages.get(0));
        sendAction.setContextAlias(forwardToAlias);
        sendAction.execute(state);
        setExecuted(true);
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    @Override
    public boolean executedAsPlanned() {
        return (recvAction.executedAsPlanned() && sendAction.executedAsPlanned());
    }

    @Override
    public void reset() {
        messages = new LinkedList<>();
        records = new LinkedList<>();
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 19 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 19 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 19 * hash + Objects.hashCode(this.recvAction);
        hash = 19 * hash + Objects.hashCode(this.sendAction);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ForwardAction other = (ForwardAction) obj;
        return true;
    }

}
