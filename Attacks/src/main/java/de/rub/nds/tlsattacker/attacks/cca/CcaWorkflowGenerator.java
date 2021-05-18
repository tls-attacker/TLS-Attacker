/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EmptyClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

public class CcaWorkflowGenerator {
    /**
     *
     * @param  tlsConfig
     *                         the config
     * @param  ccaWorkflowType
     *                         the ccaWorkflowType of workflow to execute
     * @return                 returns a WorkflowTrace ready for execution
     */
    public static WorkflowTrace generateWorkflow(Config tlsConfig, CcaCertificateManager ccaCertificateManager,
        CcaWorkflowType ccaWorkflowType, CcaCertificateType ccaCertificateType) {
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        CertificateMessage certificateMessage;
        CertificateMessage certificateMessage2;
        if (ccaWorkflowType != null) {
            switch (ccaWorkflowType) {
                case CRT_CKE_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT_CKE_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new FinishedMessage(tlsConfig)));
                    break;
                case CRT_CKE_ZFIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    FinishedMessage crtCkeZfin = new FinishedMessage(tlsConfig);
                    crtCkeZfin.setVerifyData(Modifiable.explicit(new byte[HandshakeByteLength.VERIFY_DATA]));
                    trace.addTlsAction(new SendAction(crtCkeZfin));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CKE_CCS_CRT_FIN_CCS_RND:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), certificateMessage,
                        new FinishedMessage(tlsConfig), new ChangeCipherSpecMessage(tlsConfig), certificateMessage));
                    break;
                case CRT_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage, new FinishedMessage(tlsConfig)));
                    break;
                case CRT_ZFIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    FinishedMessage crtZfin = new FinishedMessage(tlsConfig);
                    crtZfin.setVerifyData(Modifiable.explicit(new byte[HandshakeByteLength.VERIFY_DATA]));
                    trace.addTlsAction(new SendAction(certificateMessage, crtZfin));
                    break;
                case CRT_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage, new ChangeCipherSpecMessage(tlsConfig),
                        new FinishedMessage(tlsConfig)));
                    break;
                case CRT_CKE_VRFY_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT1_CRT2_CKE_VRFY1_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    certificateMessage2 = CcaCertificateGenerator.generateCertificate(ccaCertificateManager,
                        CcaCertificateType.CLIENT_INPUT);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendAction(certificateMessage2));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT1_CRT2_CKE_VRFY2_CCS_FIN:
                    certificateMessage = CcaCertificateGenerator.generateCertificate(ccaCertificateManager,
                        CcaCertificateType.CLIENT_INPUT);
                    certificateMessage2 =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendAction(certificateMessage2));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT1_CKE_CRT2_CKE2_VRFY1_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    certificateMessage2 = CcaCertificateGenerator.generateCertificate(ccaCertificateManager,
                        CcaCertificateType.CLIENT_INPUT);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(certificateMessage2));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT1_CKE_CRT2_CKE2_VRFY2_CCS_FIN:
                    certificateMessage = CcaCertificateGenerator.generateCertificate(ccaCertificateManager,
                        CcaCertificateType.CLIENT_INPUT);
                    certificateMessage2 =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(certificateMessage2));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT_ECKE_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage, new EmptyClientKeyExchangeMessage(),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CKE_CRT_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CKE_CRT_VRFY_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig),
                        new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT_CKE_CCS_VRFY_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig)));
                    trace.addTlsAction(
                        new SendAction(new CertificateVerifyMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                case CRT_VRFY_CKE_CCS_FIN:
                    certificateMessage =
                        CcaCertificateGenerator.generateCertificate(ccaCertificateManager, ccaCertificateType);
                    trace.addTlsAction(new SendAction(certificateMessage));
                    trace.addTlsAction(new SendAction(new CertificateVerifyMessage(tlsConfig)));
                    trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
                    trace.addTlsAction(
                        new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        return trace;
    }
}
