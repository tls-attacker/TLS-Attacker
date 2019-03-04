/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.Lucky13CommandConfig;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.transport.tcp.proxy.TimingProxyClientTcpTransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes the Lucky13 attack test
 */
public class Lucky13Attacker extends Attacker<Lucky13CommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(Lucky13Attacker.class);

    private final Map<Integer, List<Long>> results;

    private long lastResult;

    private final Config tlsConfig;

    public Lucky13Attacker(Lucky13CommandConfig config, Config baseConfig) {
        super(config, baseConfig);
        tlsConfig = getTlsConfig();
        results = new HashMap<>();
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
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
            LOGGER.error(ex);
        }
    }

    public void executeAttackRound(Record record) {
        tlsConfig.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.TCP_PROXY_TIMING);
        tlsConfig.setWorkflowExecutorShouldClose(true);

        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.FULL,
                RunningModeType.CLIENT);

        SendAction sendAction = (SendAction) trace.getLastSendingAction();
        LinkedList<AbstractRecord> records = new LinkedList<>();
        records.add(record);
        sendAction.setRecords(records);

        ReceiveAction action = new ReceiveAction();

        AlertMessage alertMessage = new AlertMessage(tlsConfig);
        List<ProtocolMessage> messages = new LinkedList<>();
        messages.add(alertMessage);
        action.setExpectedMessages(messages);
        trace.addTlsAction(action);

        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
        }

        TimingProxyClientTcpTransportHandler transportHandler = (TimingProxyClientTcpTransportHandler) state
                .getTlsContext().getTransportHandler();
        lastResult = transportHandler.getLastMeasurement();
        try {
            transportHandler.closeConnection();
        } catch (IOException e) {
            LOGGER.warn(e.getMessage());
        }
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {

        }
    }

    private Record createRecordWithPadding(int p, CipherSuite suite) {
        byte[] padding = createPaddingBytes(p);
        int recordLength = AlgorithmResolver.getCipher(suite).getBlocksize() * config.getBlocks();
        if (recordLength < padding.length) {
            throw new ConfigurationException("Padding too large");
        }
        /* create a message with arbitrary bytes */
        int messageSize = recordLength - padding.length;
        byte[] message = new byte[messageSize];
        new Random().nextBytes(message);
        byte[] plain = ArrayConverter.concatenate(message, padding);
        return createRecordWithPlainData(plain);
    }

    private Record createRecordWithPlainData(byte[] plain) {
        Record r = new Record();
        r.prepareComputations();
        ModifiableByteArray plainData = new ModifiableByteArray();
        VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
        plainData.setModification(modifier);
        r.getComputations().setPlainRecordBytes(plainData);
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
    protected Boolean isVulnerable() {
        Boolean vulnerable = false;
        StringBuilder commands = new StringBuilder();
        List<CipherSuite> suites = tlsConfig.getDefaultClientSupportedCiphersuites();
        for (CipherSuite suite : suites) {
            results.clear();
            LOGGER.info("Testing ciphersuite {}", suite);
            tlsConfig.setDefaultClientSupportedCiphersuites(suite);
            tlsConfig.setDefaultServerSupportedCiphersuites(suite);
            tlsConfig.setDefaultSelectedCipherSuite(suite);
            String[] paddingStrings = config.getPaddings().split(",");
            int[] paddings = new int[paddingStrings.length];
            for (int i = 0; i < paddingStrings.length; i++) {
                paddings[i] = Integer.parseInt(paddingStrings[i]);
            }
            for (int i = 0; i < config.getMeasurements(); i++) {
                LOGGER.info("Starting round {}", i);
                for (int p : paddings) {
                    Record record = createRecordWithPadding(p, suite);
                    executeAttackRound(record);
                    LOGGER.info("Padding: {}, Measured {}", p, lastResult);
                    if (results.get(p) == null) {
                        results.put(p, new LinkedList<Long>());
                    }
                    // remove the first 20% of measurements
                    if (i > (config.getMeasurements() / 4) - 1) {
                        results.get(p).add(lastResult);
                    }
                }
            }

            StringBuilder medians = new StringBuilder();
            for (int padding : paddings) {
                List<Long> rp = (List) ((LinkedList) results.get(padding)).clone();
                Collections.sort(rp);
                LOGGER.info("Padding: {}", padding);
                long median = rp.get(rp.size() / 2);
                LOGGER.info("Median: {}", median);
                medians.append(median).append(",");
            }
            LOGGER.info("Medians: {}", medians);

            if (config.getMonaFile() != null) {
                for (int i = 0; i < paddings.length - 1; i++) {
                    for (int j = i + 1; j < paddings.length; j++) {
                        String fileName = config.getMonaFile() + "-" + paddings[i] + "-" + paddings[j] + "-"
                                + suite.name() + ".csv";
                        String[] delimiters = { (";" + paddings[i] + ";"), (";" + paddings[j] + ";") };
                        createMonaFile(fileName, delimiters, results.get(paddings[i]), results.get(paddings[j]));
                        String command = "java -jar " + config.getMonaJar() + " --inputFile=" + fileName
                                + " --name=lucky13-" + suite.name().replace('_', '-') + "-" + paddings[i] + "-"
                                + paddings[j] + " --lowerBound=0.3 --upperBound=0.5";
                        LOGGER.info("Run mona timing lib with: " + command);
                        commands.append(command);
                        commands.append(System.getProperty("line.separator"));
                    }
                }
            }
        }
        LOGGER.info("All commands at once: \n{}", commands);
        LOGGER.warn("Vulnerability has to be tested using the mona timing lib.");
        return vulnerable;
    }
}
