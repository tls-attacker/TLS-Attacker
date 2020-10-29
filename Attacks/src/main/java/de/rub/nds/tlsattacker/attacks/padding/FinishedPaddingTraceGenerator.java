/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import java.util.LinkedList;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

/**
 *
 */
public class FinishedPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     *
     * @param type
     */
    public FinishedPaddingTraceGenerator(PaddingRecordGeneratorType type) {
        super(type);
    }

    /**
     *
     * @param config
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        RunningModeType runningMode = config.getDefaultRunningMode();
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
                runningMode);
        if (runningMode == RunningModeType.CLIENT) {
            // remove receive Server CCS, FIN
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
        }
        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<AbstractRecord> recordList = new LinkedList<>();
        for (ProtocolMessage msg : sendAction.getMessages()) {
            if (msg instanceof FinishedMessage) {
                recordList.add(vector.createRecord());
            } else {
                recordList.add(new Record(config));
            }
        }
        sendAction.setRecords(recordList);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
