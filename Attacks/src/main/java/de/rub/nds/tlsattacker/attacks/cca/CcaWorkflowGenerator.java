/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class CcaWorkflowGenerator {
    /**
     *
     * @param tlsConfig
     *            the config
     * @param type
     *            the type of workflow to execute
     * @param certMessage
     *            the certificateMessage to be sent in the workflow
     * @return returns a WorkflowTrace ready for execution
     */
    public static WorkflowTrace generateWorkflow(Config tlsConfig, CcaWorkflowType type, CertificateMessage certMessage) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
        if (type != null) {
            switch (type) {
                case CRT_CKE_CCS_FIN:
                    trace.addTlsAction(new SendAction(certMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(
                            tlsConfig)));
                    break;
                case CRT_CKE_FIN:
                    trace.addTlsAction(new SendAction(certMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new FinishedMessage(tlsConfig)));
                    break;
                case CRT_CKE_ZFIN:
                    trace.addTlsAction(new SendAction(certMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    FinishedMessage fin = new FinishedMessage(tlsConfig);
                    fin.setVerifyData(Modifiable.explicit(new byte[HandshakeByteLength.VERIFY_DATA]));
                    trace.addTlsAction(new SendAction(fin));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(
                            tlsConfig)));
                    break;
                case CKE_CCS_CRT_FIN_CCS_RND:
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), certMessage,
                            new FinishedMessage(tlsConfig), new ChangeCipherSpecMessage(tlsConfig), certMessage));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }
}
