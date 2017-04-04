/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested
 * server is vulnerable to poodle.
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class PaddingOracleAttacker extends Attacker<PaddingOracleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(PaddingOracleAttacker.class);

    private final List<ProtocolMessage> lastMessages;
    private final TlsConfig tlsConfig;

    public PaddingOracleAttacker(PaddingOracleCommandConfig config) {
        super(config, false);
        tlsConfig = config.createConfig();
        lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    public void executeAttackRound(Record record) {
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        ApplicationMessage applicationMessage = new ApplicationMessage(tlsConfig);
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.getConfiguredRecords().add(record);
        trace.add(sendAction);
        AlertMessage alertMessage = new AlertMessage(tlsConfig);
        trace.add(new ReceiveAction(alertMessage));

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
        }
        lastMessages.add(trace.getAllActuallyReceivedMessages().get(trace.getAllActuallyReceivedMessages().size() - 1));
    }

    private List<Record> createRecordsWithPlainData() {
        List<Record> records = new LinkedList<>();
        for (int i = 0; i < 64; i++) {
            byte[] padding = createPaddingBytes(i);
            int messageSize = config.getBlockSize() - (padding.length % config.getBlockSize());
            byte[] message = new byte[messageSize];
            byte[] plain = ArrayConverter.concatenate(message, padding);
            Record r = createRecordWithPlainData(plain);
            records.add(r);
        }
        Record r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255 });
        records.add(r);

        r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
                (byte) 255, (byte) 255, (byte) 255 });
        records.add(r);

        return records;
    }

    private Record createRecordWithPlainData(byte[] plain) {
        Record r = new Record();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.setPlainRecordBytes(plainData);
        return r;
    }

    private List<Record> createRecordsWithModifiedPadding() {
        List<Record> records = new LinkedList<>();

        Record r = new Record();
        ModifiableByteArray padding = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
        padding.setModification(modifier);
        r.setPadding(padding);
        records.add(r);

        return records;
    }

    private List<Record> createRecordsWithModifiedMac() {
        List<Record> records = new LinkedList<>();

        Record r = new Record();
        ModifiableByteArray mac = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1, 1, 1 }, 0);
        mac.setModification(modifier);
        r.setMac(mac);
        records.add(r);

        return records;
    }

    private byte[] createPaddingBytes(int padding) {
        byte[] paddingBytes = new byte[padding + 1];
        for (int i = 0; i < paddingBytes.length; i++) {
            paddingBytes[i] = (byte) padding;
        }
        return paddingBytes;
    }

    @Override
    public Boolean isVulnerable() {
        List<Record> records = new LinkedList<>();
        records.addAll(createRecordsWithPlainData());
        records.addAll(createRecordsWithModifiedMac());
        records.addAll(createRecordsWithModifiedPadding());
        for (Record record : records) {
            executeAttackRound(record);

        }
        LOGGER.info("All the attack runs executed. The following messages arrived at the ends of the connections");
        LOGGER.info("If there are different messages, this could indicate the server does not process padding correctly");

        LinkedHashSet<ProtocolMessage> pmSet = new LinkedHashSet<>();
        for (int i = 0; i < lastMessages.size(); i++) {
            ProtocolMessage pm = lastMessages.get(i);
            pmSet.add(pm);
            Record r = records.get(i);
            LOGGER.info("----- NEXT TLS CONNECTION WITH MODIFIED APPLICATION DATA RECORD -----");
            if (r.getPlainRecordBytes() != null) {
                LOGGER.info("Plain record bytes of the modified record: ");
                LOGGER.info(ArrayConverter.bytesToHexString(r.getPlainRecordBytes().getValue()));
                LOGGER.info("Last protocol message in the protocol flow");
            }
            LOGGER.info(pm.toString());
        }
        List<ProtocolMessage> pmSetList = new LinkedList<>(pmSet);

        if (pmSet.size() == 1) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, NOT vulnerable, one message found: {}", tlsConfig.getHost(),
                    pmSetList);
            return false;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (?), more messages found, recheck in debug mode: {}",
                    tlsConfig.getHost(), pmSetList);
            return true;
        }
    }

}
