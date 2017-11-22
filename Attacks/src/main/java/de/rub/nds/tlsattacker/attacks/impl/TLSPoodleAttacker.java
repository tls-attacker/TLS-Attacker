/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a poodle attack. It logs an error in case the tested server is
 * vulnerable to poodle.
 */
public class TLSPoodleAttacker extends Attacker<TLSPoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(TLSPoodleAttacker.class);

    public TLSPoodleAttacker(TLSPoodleCommandConfig config) {
        super(config, false);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = config.createConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(
                WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        ModifiableByteArray padding = new ModifiableByteArray();
        // we xor just the first byte in the padding
        // if the padding was {0x02, 0x02, 0x02}, it becomes {0x03, 0x02, 0x02}
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
        padding.setModification(modifier);
        ApplicationMessage applicationMessage = new ApplicationMessage(tlsConfig);
        Record r = new Record();
        r.setPadding(padding);
        SendAction sendAction = new SendAction(applicationMessage);
        List<AbstractRecord> recordList = new LinkedList<>();
        recordList.add(r);
        sendAction.setRecords(recordList);
        AlertMessage alertMessage = new AlertMessage(tlsConfig);
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new ReceiveAction(alertMessage));

        State state = new State(tlsConfig, trace);

        try {
            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow");
            LOGGER.debug(ex);
            return null;
        }
        if (state.getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
            return false;
        } else {
            LOGGER.info("Vulnerable(?). The modified message padding was not identified, the server does NOT respond with an alert message");
            return true;
        }
    }
}
