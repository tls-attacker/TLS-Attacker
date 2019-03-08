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
import de.rub.nds.tlsattacker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;

/**
 *
 */
public class ClassicPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     *
     * @param recordGeneratorType
     */
    public ClassicPaddingTraceGenerator(PaddingRecordGeneratorType recordGeneratorType) {
        super(recordGeneratorType);
    }

    /**
     *
     * @param config
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(config).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
                RunningModeType.CLIENT);
        ApplicationMessage applicationMessage = new ApplicationMessage(config);
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.setRecords(new LinkedList<AbstractRecord>());
        sendAction.getRecords().add(vector.createRecord());
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
