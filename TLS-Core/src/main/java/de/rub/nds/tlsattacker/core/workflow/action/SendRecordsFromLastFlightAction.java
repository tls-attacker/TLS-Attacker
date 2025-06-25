/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.protocol.exception.WorkflowExecutionException;
import de.rub.nds.protocol.util.DeepCopyUtil;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import java.util.LinkedList;
import java.util.List;

public class SendRecordsFromLastFlightAction extends CommonSendAction {

    public SendRecordsFromLastFlightAction() {
        super();
    }

    public SendRecordsFromLastFlightAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        List<Record> lastRecords = getLastSendingAction(state.getWorkflowTrace()).getSentRecords();
        List<Record> duplicatedRecords = DeepCopyUtil.deepCopy(lastRecords);
        for (int i = 0; i < duplicatedRecords.size(); i++) {
            duplicatedRecords
                    .get(i)
                    .setCleanProtocolMessageBytes(
                            Modifiable.explicit(
                                    lastRecords.get(i).getCleanProtocolMessageBytes().getValue()));
        }
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        configurationList.add(
                new SpecificSendLayerConfiguration<>(ImplementedLayers.RECORD, duplicatedRecords));
        return ActionHelperUtil.sortAndAddOptions(
                state.getTlsContext(connectionAlias).getLayerStack(),
                true,
                getActionOptions(),
                configurationList);
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
