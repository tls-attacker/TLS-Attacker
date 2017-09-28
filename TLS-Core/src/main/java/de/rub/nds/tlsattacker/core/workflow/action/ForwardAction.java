/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ForwardAction extends MessageAction implements ReceivingAction, SendingAction {

    private static final Logger LOGGER = LogManager.getLogger(ForwardAction.class);

    private String receiveFromAlias = null;
    private String forwardToAlias = null;

    @XmlTransient
    private Boolean executedAsPlanned = null;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
            @XmlElement(type = ArbitraryMessage.class, name = "ArbitraryMessage"),
            @XmlElement(type = CertificateMessage.class, name = "Certificate"),
            @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
            @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
            @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
            @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
            @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
            @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
            @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
            @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
            @XmlElement(type = FinishedMessage.class, name = "Finished"),
            @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
            @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
            @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
            @XmlElement(type = AlertMessage.class, name = "Alert"),
            @XmlElement(type = ApplicationMessage.class, name = "Application"),
            @XmlElement(type = ChangeCipherSpecMessage.class, name = "ChangeCipherSpec"),
            @XmlElement(type = SSL2ClientHelloMessage.class, name = "SSL2ClientHello"),
            @XmlElement(type = SSL2ServerHelloMessage.class, name = "SSL2ServerHello"),
            @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
            @XmlElement(type = UnknownHandshakeMessage.class, name = "UnknownHandshakeMessage"),
            @XmlElement(type = RetransmitMessage.class, name = "RetransmitMessage"),
            @XmlElement(type = HelloRequestMessage.class, name = "HelloRequest"),
            @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat"),
            @XmlElement(type = EncryptedExtensionsMessage.class, name = "EncryptedExtensionMessage"),
            @XmlElement(type = HelloRetryRequestMessage.class, name = "HelloRetryRequest") })
    protected List<ProtocolMessage> receivedMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
            @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> receivedRecords;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
            @XmlElement(type = ArbitraryMessage.class, name = "ArbitraryMessage"),
            @XmlElement(type = CertificateMessage.class, name = "Certificate"),
            @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
            @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
            @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
            @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
            @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
            @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
            @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
            @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
            @XmlElement(type = FinishedMessage.class, name = "Finished"),
            @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
            @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
            @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
            @XmlElement(type = AlertMessage.class, name = "Alert"),
            @XmlElement(type = ApplicationMessage.class, name = "Application"),
            @XmlElement(type = ChangeCipherSpecMessage.class, name = "ChangeCipherSpec"),
            @XmlElement(type = SSL2ClientHelloMessage.class, name = "SSL2ClientHello"),
            @XmlElement(type = SSL2ServerHelloMessage.class, name = "SSL2ServerHello"),
            @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
            @XmlElement(type = UnknownHandshakeMessage.class, name = "UnknownHandshakeMessage"),
            @XmlElement(type = RetransmitMessage.class, name = "RetransmitMessage"),
            @XmlElement(type = HelloRequestMessage.class, name = "HelloRequest"),
            @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat"),
            @XmlElement(type = EncryptedExtensionsMessage.class, name = "EncryptedExtensionMessage"),
            @XmlElement(type = HelloRetryRequestMessage.class, name = "HelloRetryRequest") })
    protected List<ProtocolMessage> sendMessages;

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
            @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> sendRecords;

    public ForwardAction() {
        super();
    }

    public ForwardAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public ForwardAction(ProtocolMessage... messages) {
        this(Arrays.asList(messages));
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException, IOException {
        if (receiveFromAlias == null) {
            throw new WorkflowExecutionException("Can't execute ForwardAction with empty receiveFromAlias");
        }
        if (forwardToAlias == null) {
            throw new WorkflowExecutionException("Can't execute ForwardAction with empty forwardToAlias");
        }
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        TlsContext receivingCtx = state.getTlsContext(receiveFromAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessages(messages, receivingCtx);
        receivedRecords = result.getRecordList();
        receivedMessages = result.getMessageList();

        String expected = getReadableString(receivedMessages);
        LOGGER.debug("Receive Expected (" + receiveFromAlias + "): " + expected);
        String received = getReadableString(receivedMessages);
        LOGGER.info("Received Messages (" + receiveFromAlias + "): " + received);

        executedAsPlanned = checkMessageListsEquals(messages, receivedMessages);

        for (ProtocolMessage msg : receivedMessages) {
            LOGGER.debug("Applying " + msg.toCompactString() + " to forward context " + forwardToAlias);
            ProtocolMessageHandler h = msg.getHandler(state.getTlsContext(forwardToAlias));
            h.adjustTLSContext(msg);
        }

        TlsContext forwardToCtx = state.getTlsContext(forwardToAlias);
        LOGGER.info("Forwarding messages (" + forwardToAlias + "): " + getReadableString(messages));

        try {
            result = sendMessageHelper.sendMessages(receivedMessages, receivedRecords, forwardToCtx);
            sendMessages = result.getMessageList();
            sendRecords = result.getRecordList();
            if (executedAsPlanned) {
                executedAsPlanned = checkMessageListsEquals(sendMessages, messages);
            }
            setExecuted(true);
        } catch (IOException E) {
            LOGGER.debug(E);
            executedAsPlanned = false;
            setExecuted(false);
        }
    }

    public String getReceiveFromAlias() {
        return receiveFromAlias;
    }

    public void setReceiveFromAlias(String receiveFromAlias) {
        this.receiveFromAlias = receiveFromAlias;
    }

    public String getForwardToAlias() {
        return forwardToAlias;
    }

    public void setForwardToAlias(String forwardToAlias) {
        this.forwardToAlias = forwardToAlias;
    }

    // TODO: yes, the correct way would be implement equals() for all
    // ProtocolMessages...
    private boolean checkMessageListsEquals(List<ProtocolMessage> expectedMessages, List<ProtocolMessage> actualMessages) {
        if (actualMessages.size() != expectedMessages.size()) {
            return false;
        } else {
            for (int i = 0; i < actualMessages.size(); i++) {
                if (!actualMessages.get(i).getClass().equals(expectedMessages.get(i).getClass())) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    @Override
    public void reset() {
        receivedMessages = null;
        receivedRecords = null;
        sendMessages = null;
        sendRecords = null;
        executedAsPlanned = false;
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return receivedMessages;
    }

    @Override
    public List<AbstractRecord> getReceivedRecords() {
        return receivedRecords;
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return sendMessages;
    }

    @Override
    public List<AbstractRecord> getSendRecords() {
        return sendRecords;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 17 * hash + Objects.hashCode(this.receiveFromAlias);
        hash = 17 * hash + Objects.hashCode(this.forwardToAlias);
        hash = 17 * hash + Objects.hashCode(this.executedAsPlanned);
        hash = 17 * hash + Objects.hashCode(this.receivedMessages);
        hash = 17 * hash + Objects.hashCode(this.receivedRecords);
        hash = 17 * hash + Objects.hashCode(this.sendMessages);
        hash = 17 * hash + Objects.hashCode(this.sendRecords);
        hash = 17 * hash + Objects.hashCode(this.messages);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ForwardAction other = (ForwardAction) obj;
        if (!Objects.equals(this.receiveFromAlias, other.receiveFromAlias)) {
            return false;
        }
        if (!Objects.equals(this.forwardToAlias, other.forwardToAlias)) {
            return false;
        }
        if (!Objects.equals(this.executedAsPlanned, other.executedAsPlanned)) {
            return false;
        }
        if (!Objects.equals(this.receivedMessages, other.receivedMessages)) {
            return false;
        }
        if (!Objects.equals(this.receivedRecords, other.receivedRecords)) {
            return false;
        }
        if (!Objects.equals(this.sendMessages, other.sendMessages)) {
            return false;
        }
        if (!Objects.equals(this.sendRecords, other.sendRecords)) {
            return false;
        }
        return Objects.equals(this.messages, other.messages);
    }

}
