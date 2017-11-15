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
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerCommandConfig;
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
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.transport.udp.timing.TimingClientUdpTransportHandler;
import java.nio.charset.Charset;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author florian
 */
public class PskBruteForcer extends Attacker<PskBruteForcerCommandConfig> {
    private static final Logger LOGGER = LogManager.getLogger(PskBruteForcer.class);
    //private TlsContext context;
    //private RecordLayer recordLayer;
    //private List<TLSAction> actionList;
    //private TimingClientUdpTransportHandler transportHandler;
    //private WorkflowExecutor workflowExecutor;
    //private WorkflowTrace trace;
    //private final Config tlsConfig;

    public PskBruteForcer(PskBruteForcerCommandConfig config) {
        super(config, false);
        //tlsConfig = config.createConfig();
        
        
        
    }

    @Override
    public void executeAttack() {
        WorkflowTrace trace = executeProtocolFlow();
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
        // messageList = new LinkedList<>();
        // context.setPSKIdentity(ArrayConverter.hexStringToByteArray("436c69656e745f6964656e74697479"));
        // messageList.add(new PskClientKeyExchangeMessage());
        // messageList.add(new ChangeCipherSpecMessage());
        // trace.addTlsAction(new SendAction(messageList));
        // messageList = new LinkedList<>();
        // trace.addTlsAction(new ReceiveAction(messageList));
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

        // context.setPSKIdentity();
    }
    
    private WorkflowTrace executeProtocolFlow() {
        Config tlsConfig = config.createConfig();
        tlsConfig.setDefaultPSKKey(ArrayConverter.hexStringToByteArray("1a2b3c4d"));
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createHelloWorkflow();
        trace.addTlsAction(new SendAction(new PskClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        PskClientKeyExchangeMessage message = (PskClientKeyExchangeMessage) WorkflowTraceUtil.getFirstSendMessage(
                HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);

       
        message.prepareComputations();
        message.setIdentity("Client_Identity".getBytes(Charset.forName("UTF-8")));
        workflowExecutor.executeWorkflow();
        return trace;
    }
}