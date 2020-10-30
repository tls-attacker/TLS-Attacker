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
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

/**
 *
 */
public class ClassicDynamicPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     *
     * @param recordGeneratorType
     */
    public ClassicDynamicPaddingTraceGenerator(PaddingRecordGeneratorType recordGeneratorType) {
        super(recordGeneratorType);
    }

    /**
     *
     * @param config
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        RunningModeType runningMode = config.getDefaultRunningMode();
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace = factory.createTlsEntryWorkflowtrace(config.getDefaultClientConnection());

        ApplicationMessage applicationMessage = new ApplicationMessage(config);
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.setRecords(new LinkedList<AbstractRecord>());
        sendAction.getRecords().add(vector.createRecord());

        switch (runningMode) {
            case CLIENT:
                trace.addTlsAction(new SendAction(new ClientHelloMessage(config)));
                trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
                trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                trace.addTlsAction(sendAction);
                trace.addTlsAction(new GenericReceiveAction());
                break;
            case SERVER:
                trace.addTlsAction(new ReceiveTillAction(new ClientHelloMessage(config)));
                // sh, cert, ske, shd
                trace.addTlsAction(new SendAction(new ServerHelloMessage(config)));
                trace.addTlsAction(new SendDynamicServerCertificateAction());
                trace.addTlsAction(new SendDynamicServerKeyExchangeAction());
                trace.addTlsAction(new SendAction(new ServerHelloDoneMessage(config)));

                trace.addTlsAction(new ReceiveTillAction(new FinishedMessage(config)));
                trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
                // assume client sends first app data
                trace.addTlsAction(new GenericReceiveAction());
                trace.addTlsAction(sendAction);
                trace.addTlsAction(new GenericReceiveAction());
                break;
            default:
                throw new RuntimeException("Unknown/Unsupported runningMode " + runningMode);
        }
        return trace;
    }
}
