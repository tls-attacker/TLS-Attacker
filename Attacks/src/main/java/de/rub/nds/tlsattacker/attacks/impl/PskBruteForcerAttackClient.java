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
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerAttackClientCommandConfig;
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
import de.rub.nds.tlsattacker.core.protocol.preparator.PskClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

/**
 *
 * @author florian
 */
public class PskBruteForcerAttackClient extends Attacker<PskBruteForcerAttackClientCommandConfig> {
    private static final Logger LOGGER = LogManager.getLogger(PskBruteForcerAttackClient.class);
    private ServerTcpTransportHandler transportHandler;
    private RecordLayer recordLayer;
    private TlsContext tlsContext;
    private Config tlsConfig;

    // private DefaultChooser chooser;

    public PskBruteForcerAttackClient(PskBruteForcerAttackClientCommandConfig config) {
        // chooser= tlsContext.getChooser();
        super(config, false);
        LOGGER.info(tlsContext.getChooser());
        // tlsConfig = config.createConfig();

    }

    @Override
    public void executeAttack() {
        executeProtocolFlowToClient();
    }

    public void executeAttackWithoutPskTable() {
    }

    public void executeAttackWithPskTable() {
    }

    @Override
    public Boolean isVulnerable() {
        return true;
    }

    private void executeProtocolFlowToClient() {
        tlsConfig = config.createConfig();
        // chooser = (DefaultChooser)
        // ChooserFactory.getChooser(tlsConfig.getChooserType(), tlsContext,
        // tlsConfig);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createHelloWorkflow();
        State state = new State(tlsConfig, trace);
        state.setWorkflowTrace(trace);
        state.getTlsContext().setClientSupportedCiphersuites(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        tlsConfig.setDefaultSelectedCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA);
        trace.removeTlsAction(1);
        trace.removeTlsAction(0);
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(tlsConfig), new ServerHelloDoneMessage(tlsConfig)));

        trace.addTlsAction(new ReceiveAction(new PskClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        // PskClientKeyExchangeMessage message = (PskClientKeyExchangeMessage)
        // WorkflowTraceUtil.getFirstSendMessage(
        // HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);

        workflowExecutor.executeWorkflow();
        if (!trace.executedAsPlanned()) {
            // tlsConfig
            tlsConfig.setDefaultPSKKey("1a2b3c".getBytes(Charset.forName("UTF-8")));
            PskClientKeyExchangeMessage msg = new PskClientKeyExchangeMessage(tlsConfig);
            ProtocolMessage msg2 = trace.getReceivingActions().get(1).getReceivedMessages().get(0);
            PskClientKeyExchangeMessage msg3 = (PskClientKeyExchangeMessage) msg2;
            LOGGER.info("-.------------------------------");
            LOGGER.info(ArrayConverter.bytesToHexString(msg3.getComputations().getPremasterSecret()));

            // LOGGER.info(tlsContext.getChooser().getConfig().getDefaultPSKKey());
            PskClientKeyExchangePreparator preparator = new PskClientKeyExchangePreparator(ChooserFactory.getChooser(
                    tlsConfig.getChooserType(), tlsContext, tlsConfig), msg3);
            //byte[] premasterSecret = preparator.generatePremasterSecret();
            //tlsContext.setPreMasterSecret(premasterSecret);

            // AbstractRecord finished =
            // trace.getReceivingActions().get(1).getReceivedRecords().get(2);
            // recordLayer.decryptRecord(finished);
            // preparator.prepareHandshakeMessageContents();
            // LOGGER.info(ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret()));
            // LOGGER.info(ArrayConverter.bytesToHexString(preparator.generatePremasterSecret()));

        }
        // LOGGER.info(state.getWorkflowTrace().toString());
        // LOGGER.info(trace.getLastMessageAction().toString());
    }
}