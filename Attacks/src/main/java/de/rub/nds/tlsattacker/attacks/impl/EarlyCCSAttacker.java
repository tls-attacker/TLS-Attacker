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

import de.rub.nds.tlsattacker.attacks.actions.EarlyCcsAction;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class EarlyCCSAttacker extends Attacker<EarlyCCSCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public enum TargetVersion {

        /**
         *
         */
        OPENSSL_1_0_0,
        /**
         *
         */
        OPENSSL_1_0_1
    };

    /**
     *
     * @param config
     * @param baseConfig
     */
    public EarlyCCSAttacker(EarlyCCSCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        EarlyCcsVulnerabilityType earlyCcsVulnerabilityType = getEarlyCcsVulnerabilityType();
        switch (earlyCcsVulnerabilityType) {
            case VULN_EXPLOITABLE:
            case VULN_NOT_EXPLOITABLE:
                return true;
            case NOT_VULNERABLE:
                return false;
            case UNKNOWN:
                return null;
        }
        return null;
    }

    /**
     *
     * @param targetVersion
     * @return
     */
    public boolean checkTargetVersion(TargetVersion targetVersion) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setFiltersKeepUserSettings(false);
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(tlsConfig);
        WorkflowTrace workflowTrace = factory.createTlsEntryWorkflowtrace(tlsConfig.getDefaultClientConnection());

        workflowTrace.addTlsAction(new SendAction(new ClientHelloMessage(tlsConfig)));

        List<ProtocolMessage> messageList = new LinkedList<>();
        messageList.add(new ServerHelloMessage(tlsConfig));
        messageList.add(new CertificateMessage(tlsConfig));
        messageList.add(new ServerHelloDoneMessage(tlsConfig));
        workflowTrace.addTlsAction(new ReceiveAction(messageList));

        ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(tlsConfig);
        workflowTrace.addTlsAction(new SendAction(changeCipherSpecMessage));

        byte[] emptyMasterSecret = new byte[0];
        workflowTrace.addTlsAction(new ChangeMasterSecretAction(emptyMasterSecret));
        workflowTrace.addTlsAction(new ActivateEncryptionAction());

        workflowTrace.addTlsAction(new EarlyCcsAction(targetVersion == TargetVersion.OPENSSL_1_0_0));

        if (targetVersion != TargetVersion.OPENSSL_1_0_0) {
            workflowTrace.addTlsAction(new ChangeMasterSecretAction(emptyMasterSecret));
        }
        workflowTrace.addTlsAction(new SendAction(new FinishedMessage(tlsConfig)));

        messageList = new LinkedList<>();
        messageList.add(new ChangeCipherSpecMessage(tlsConfig));
        messageList.add(new FinishedMessage(tlsConfig));
        workflowTrace.addTlsAction(new ReceiveAction(messageList));

        State state = new State(tlsConfig, workflowTrace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.ALERT, workflowTrace)) {
            CONSOLE.info("Not vulnerable (definitely), Alert message found");
            return false;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, workflowTrace)) {
            CONSOLE.warn("Vulnerable (definitely), Finished message found");
            return true;
        } else {
            CONSOLE.info("Not vulnerable (probably), No Finished message found, yet also no alert");
            return false;
        }
    }

    /**
     *
     * @return
     */
    public EarlyCcsVulnerabilityType getEarlyCcsVulnerabilityType() {
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_0)) {
            return EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE;
        }
        if (checkTargetVersion(TargetVersion.OPENSSL_1_0_1)) {
            return EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
        }
        return EarlyCcsVulnerabilityType.NOT_VULNERABLE;
    }
}
