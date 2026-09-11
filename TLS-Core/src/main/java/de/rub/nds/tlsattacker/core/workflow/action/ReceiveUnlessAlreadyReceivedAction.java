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
import de.rub.nds.tlsattacker.core.layer.LayerStackProcessingResult;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Receives like a {@link ReceiveAction} unless the receive before it already took every protocol
 * message this one expects, in which case it does nothing and counts as executed as planned.
 *
 * <p>This is for messages a server may send either along with its last flight or on their own right
 * after it, where the trace cannot know in advance which of the two happens. A STARTTLS server that
 * greets unprompted once the upgrade is done may in TLS 1.3 send that greeting in the same flight
 * as its Finished, as it holds its application keys by then, or only once it has seen the client's
 * Finished. A plain receive for the greeting after the client's Finished would wait out its timeout
 * whenever the greeting had already come along with the server's flight. This action looks at the
 * nearest receive before it on the same connection and skips itself when that receive already holds
 * what it expects, much like {@link SendDynamicServerKeyExchangeAction} skips itself for a cipher
 * suite without a ServerKeyExchange.
 *
 * <p>Only the expected protocol messages take part in the check. The search for the previous
 * receive stops at a {@link ResetConnectionAction}, as whatever arrived before it belongs to
 * another connection.
 */
@XmlRootElement(name = "ReceiveUnlessAlreadyReceived")
public class ReceiveUnlessAlreadyReceivedAction extends ReceiveAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlTransient private boolean skipped = false;

    public ReceiveUnlessAlreadyReceivedAction() {
        super();
    }

    public ReceiveUnlessAlreadyReceivedAction(ProtocolMessage... expectedMessages) {
        super(expectedMessages);
    }

    public ReceiveUnlessAlreadyReceivedAction(
            String connectionAlias, ProtocolMessage... expectedMessages) {
        super(connectionAlias, expectedMessages);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        ReceivingAction previous = findPrecedingReceive(state.getWorkflowTrace());
        if (previous != null && receivedAllExpected(previous)) {
            LOGGER.info(
                    "Not receiving, the receive before already took the expected messages: {}",
                    toCompactString());
            skipped = true;
            setLayerStackProcessingResult(new LayerStackProcessingResult(new LinkedList<>()));
            setExecuted(true);
            return;
        }
        super.execute(state);
    }

    /**
     * Whether the action did not receive because the receive before it had already taken the
     * expected messages.
     *
     * @return true if the action skipped itself
     */
    public boolean isSkipped() {
        return skipped;
    }

    @Override
    public void reset() {
        skipped = false;
        super.reset();
    }

    @Override
    public String toString() {
        if (skipped) {
            return getClass().getSimpleName()
                    + ": (skipped, already received)\n\tExpected: "
                    + toCompactString();
        }
        return super.toString();
    }

    private ReceivingAction findPrecedingReceive(WorkflowTrace trace) {
        List<TlsAction> actions = trace.getTlsActions();
        int index = -1;
        for (int i = 0; i < actions.size(); i++) {
            if (actions.get(i) == this) {
                index = i;
                break;
            }
        }
        for (int i = index - 1; i >= 0; i--) {
            TlsAction action = actions.get(i);
            if (action instanceof ResetConnectionAction) {
                return null;
            }
            if (action instanceof ReceivingAction
                    && ((ReceivingAction) action)
                            .getAllReceivingAliases()
                            .contains(getConnectionAlias())) {
                return (ReceivingAction) action;
            }
        }
        return null;
    }

    private boolean receivedAllExpected(ReceivingAction previous) {
        if (getExpectedMessages() == null || getExpectedMessages().isEmpty()) {
            return false;
        }
        List<ProtocolMessage> received = previous.getReceivedMessages();
        if (received == null) {
            return false;
        }
        for (ProtocolMessage expected : getExpectedMessages()) {
            if (received.stream()
                    .noneMatch(message -> message.getClass().equals(expected.getClass()))) {
                return false;
            }
        }
        return true;
    }
}
