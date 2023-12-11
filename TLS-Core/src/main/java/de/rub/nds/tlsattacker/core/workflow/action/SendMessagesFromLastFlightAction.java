/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.util.DeepCopyUtil;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessagesFromLastFlightAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendMessagesFromLastFlightAction() {
        super();
    }

    public SendMessagesFromLastFlightAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        List<ProtocolMessage> lastMessages =
                getLastSendingAction(state.getWorkflowTrace()).getSentMessages();
        List<ProtocolMessage> duplicatedMessages = DeepCopyUtil.deepCopy(lastMessages);
        for (ProtocolMessage message : duplicatedMessages) {
            message.setShouldPrepareDefault(false);
        }
        return ActionHelperUtil.createSendConfiguration(
                state.getTlsContext(getConnectionAlias()),
                duplicatedMessages,
                null,
                null,
                null,
                null,
                null);
    }

    private SendingAction getLastSendingAction(WorkflowTrace trace) {
        for (int i = 0; i < trace.getSendingActions().size(); i++) {
            if (trace.getSendingActions().get(i) == this && i != 0) {
                return trace.getSendingActions().get(i - 1);
            }
        }
        throw new WorkflowExecutionException("Cannot find last sending action");
    }
}
