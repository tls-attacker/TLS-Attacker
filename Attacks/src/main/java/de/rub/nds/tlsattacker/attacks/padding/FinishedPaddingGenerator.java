/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.padding;

import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;

public class FinishedPaddingGenerator extends PaddingVectorGenerator {

    public FinishedPaddingGenerator(PaddingRecordGeneratorType type) {
        super(type);
    }

    @Override
    public List<WorkflowTrace> getPaddingOracleVectors(Config config) {
        List<WorkflowTrace> traceList = new LinkedList<>();
        for (Record record : recordGenerator.getRecords(config.getDefaultSelectedCipherSuite(),
                config.getDefaultSelectedProtocolVersion())) {
            WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(
                    WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            SendAction sendAction = (SendAction) trace.getLastSendingAction();
            LinkedList<AbstractRecord> recordList = new LinkedList<>();
            recordList.add(new Record(config));
            recordList.add(new Record(config));
            recordList.add(record);
            sendAction.setRecords(recordList);
            trace.addTlsAction(new GenericReceiveAction());
            traceList.add(trace);
        }
        return traceList;
    }

}
