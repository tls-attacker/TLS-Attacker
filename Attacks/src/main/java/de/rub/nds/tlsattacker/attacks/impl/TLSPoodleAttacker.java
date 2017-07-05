/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.config.TlsConfig;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a poodle attack. It logs an error in case the tested server is
 * vulnerable to poodle.
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
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
        TlsConfig tlsConfig = config.createConfig();
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);
        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        ModifiableByteArray padding = new ModifiableByteArray();
        // we xor just the first byte in the padding
        // if the padding was {0x02, 0x02, 0x02}, it becomes {0x03, 0x02, 0x02}
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
        padding.setModification(modifier);
        ApplicationMessage applicationMessage = new ApplicationMessage(tlsConfig);
        Record r = new Record();
        r.setPadding(padding);
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.getConfiguredRecords().add(r);
        AlertMessage alertMessage = new AlertMessage(tlsConfig);
        trace.add(new SendAction(applicationMessage));
        trace.add(new ReceiveAction(alertMessage));
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow");
            LOGGER.debug(ex);
            return null;
        }
        System.out.println(trace.toString());
        if (trace.getActualReceivedProtocolMessagesOfType(ProtocolMessageType.ALERT).size() > 0) {
            LOGGER.info("NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
            return false;
        } else if (!tlsContext.isReceivedFatalAlert()) {
            LOGGER.info("Vulnerable(?). The modified message padding was not identified, the server does NOT respond with an alert message");
            return true;
        }
        return null;
    }
}
