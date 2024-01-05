/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "PopAndSend")
public class PopAndSendAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Pop and send message with this index in message buffer. */
    private Integer index = null;

    private boolean couldPop = false;

    public PopAndSendAction() {
        super();
    }

    public PopAndSendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public PopAndSendAction(String connectionAlias, int index) {
        super(connectionAlias);
        this.index = index;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        super.execute(state);
        if (getSentMessages().isEmpty()) {
            couldPop = false;
        } else {
            couldPop = true;
        }
    }

    @Override
    public String toString() {
        String messageString =
                LogPrinter.toHumanReadableContainerList(
                        ActionHelperUtil.getDataContainersForLayer(
                                ImplementedLayers.MESSAGE, getLayerStackProcessingResult()));
        return "PopAndSendAction: index: "
                + index
                + " message: "
                + messageString
                + " exexuted: "
                + isExecuted()
                + " couldPop: "
                + couldPop
                + " connectionAlias: "
                + connectionAlias;
    }

    @Override
    public boolean executedAsPlanned() {
        return super.executedAsPlanned() && couldPop;
    }

    @Override
    public void reset() {
        super.reset();
        couldPop = false;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        List<ProtocolMessage> messages = new LinkedList<>();
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        LinkedList<ProtocolMessage> messageBuffer = tlsContext.getMessageBuffer();
        if (index != null && index >= 0) {
            if (index >= messageBuffer.size()) {
                throw new WorkflowExecutionException(
                        "Index out of bounds, trying to get element "
                                + index
                                + "of message buffer with "
                                + messageBuffer.size()
                                + "elements.");
            }
            messages.add(messageBuffer.get(index));
            messageBuffer.remove((int) index);
            tlsContext.getRecordBuffer().remove((int) index);
        } else {
            if (!messageBuffer.isEmpty()) {
                messages.add(messageBuffer.pop());
            }
        }
        return ActionHelperUtil.createSendConfiguration(
                tlsContext, messages, null, null, null, null, null);
    }
}
