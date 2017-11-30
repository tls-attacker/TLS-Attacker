/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.attacks.config.PskBruteForcerAttackClientCommandConfig;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import java.util.LinkedList;
import java.util.List;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.preparator.PskClientKeyExchangePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.security.NoSuchAlgorithmException;

public class PskBruteForcerAttackClient extends Attacker<PskBruteForcerAttackClientCommandConfig> {
    private static final Logger LOGGER = LogManager.getLogger(PskBruteForcerAttackClient.class);
    private ServerTcpTransportHandler transportHandler;
    private RecordLayer recordLayer;
    private TlsContext tlsContext;
    private Config tlsConfig;
    private RecordDecryptor decryptor;
    private ReceiveMessageHelper helper;

    // private DefaultChooser chooser;

    public PskBruteForcerAttackClient(PskBruteForcerAttackClientCommandConfig config) {
        // chooser= tlsContext.getChooser();
        super(config, false);
        tlsConfig = config.createConfig();
        tlsContext = new TlsContext(tlsConfig);
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
        LOGGER.info("--------------------------------------");

        // chooser = (DefaultChooser)
        // ChooserFactory.getChooser(tlsConfig.getChooserType(), tlsContext,
        // tlsConfig);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.SERVER);
        State state = new State(tlsConfig, trace);
        trace.removeTlsAction(1);
        trace.removeTlsAction(0);
        trace.addTlsAction(new ReceiveAction(new ClientHelloMessage(tlsConfig)));
        trace.addTlsAction(new SendAction(new ServerHelloMessage(tlsConfig), new ServerHelloDoneMessage(tlsConfig)));

        trace.addTlsAction(new ReceiveAction(new PskClientKeyExchangeMessage(tlsConfig), new ChangeCipherSpecMessage(
                tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();

        if (!trace.executedAsPlanned()) {
            // tlsConfig
            tlsConfig.setDefaultPSKKey(ArrayConverter.hexStringToByteArray("1a2b3c"));

            ProtocolMessage msg2 = trace.getReceivingActions().get(1).getReceivedMessages().get(0);
            PskClientKeyExchangeMessage msg3 = (PskClientKeyExchangeMessage) msg2;
            LOGGER.info(ArrayConverter.bytesToHexString(msg3.getComputations().getPremasterSecret()));

            // LOGGER.info(tlsContext.getChooser().getConfig().getDefaultPSKKey());
            PskClientKeyExchangePreparator preparator = new PskClientKeyExchangePreparator(tlsContext.getChooser(),
                    msg3);
            byte[] premasterSecret = preparator.generatePremasterSecret();
            tlsContext.setPreMasterSecret(premasterSecret);

            AbstractRecord finished = trace.getReceivingActions().get(1).getReceivedRecords().get(2);
            Record finished2 = (Record) finished;
            LOGGER.info("------------------------------------");
            try {
                KeySet keySet = KeySetGenerator.generateKeySet(tlsContext);
                RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
                decryptor = new RecordDecryptor(recordCipher, tlsContext);
                try {
                    decryptor.decrypt(trace.getReceivingActions().get(1).getReceivedRecords().get(2));
                } catch (CryptoException E) {
                    LOGGER.info("neeeeeeeeeeeeein");
                }

            } catch (NoSuchAlgorithmException ex) {
                throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
            }

            // decryptor = new RecordDecrypto, tlsContext);
            // decryptor.decrypt(finished);
            // helper = new ReceiveMessageHelper();
            List<AbstractRecord> list = new LinkedList();
            list.add(finished2);
            LOGGER.info(list.toString());
            // helper = new ReceiveMessageHelper();
            // helper.parseMessages(list, tlsContext);
            // trace.addTlsAction(new
            // ChangePreMasterSecretAction(premasterSecret));
            LOGGER.info(trace.executedAsPlanned());

            // preparator.prepareHandshakeMessageContents();
            // LOGGER.info(ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret()));
            // LOGGER.info(ArrayConverter.bytesToHexString(preparator.generatePremasterSecret()));

        }
        LOGGER.info(state.getWorkflowTrace().toString());
        // LOGGER.info(trace.getLastMessageAction().toString());
    }
}