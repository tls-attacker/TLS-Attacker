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
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import java.util.*;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveTillAction extends MessageAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
            @XmlElement(type = CertificateMessage.class, name = "Certificate"),
            @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
            @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
            @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
            @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
            @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
            @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
            @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
            @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
            @XmlElement(type = PskClientKeyExchangeMessage.class, name = "PSKClientKeyExchange"),
            @XmlElement(type = PWDServerKeyExchangeMessage.class, name = "PWDServerKeyExchange"),
            @XmlElement(type = PWDClientKeyExchangeMessage.class, name = "PWDClientKeyExchange"),
            @XmlElement(type = FinishedMessage.class, name = "Finished"),
            @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
            @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
            @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
            @XmlElement(type = AlertMessage.class, name = "Alert"),
            @XmlElement(type = NewSessionTicketMessage.class, name = "NewSessionTicket"),
            @XmlElement(type = ApplicationMessage.class, name = "Application"),
            @XmlElement(type = ChangeCipherSpecMessage.class, name = "ChangeCipherSpec"),
            @XmlElement(type = SSL2ClientHelloMessage.class, name = "SSL2ClientHello"),
            @XmlElement(type = SSL2ServerHelloMessage.class, name = "SSL2ServerHello"),
            @XmlElement(type = SSL2ClientMasterKeyMessage.class, name = "SSL2ClientMasterKey"),
            @XmlElement(type = SSL2ServerVerifyMessage.class, name = "SSL2ServerVerify"),
            @XmlElement(type = UnknownMessage.class, name = "UnknownMessage"),
            @XmlElement(type = UnknownHandshakeMessage.class, name = "UnknownHandshakeMessage"),
            @XmlElement(type = HelloRequestMessage.class, name = "HelloRequest"),
            @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat"),
            @XmlElement(type = SupplementalDataMessage.class, name = "SupplementalDataMessage"),
            @XmlElement(type = EncryptedExtensionsMessage.class, name = "EncryptedExtensionMessage"),
            @XmlElement(type = HttpsRequestMessage.class, name = "HttpsRequest"),
            @XmlElement(type = HttpsResponseMessage.class, name = "HttpsResponse"),
            @XmlElement(type = PskClientKeyExchangeMessage.class, name = "PskClientKeyExchange"),
            @XmlElement(type = PskDhClientKeyExchangeMessage.class, name = "PskDhClientKeyExchange"),
            @XmlElement(type = PskDheServerKeyExchangeMessage.class, name = "PskDheServerKeyExchange"),
            @XmlElement(type = PskEcDhClientKeyExchangeMessage.class, name = "PskEcDhClientKeyExchange"),
            @XmlElement(type = PskEcDheServerKeyExchangeMessage.class, name = "PskEcDheServerKeyExchange"),
            @XmlElement(type = PskRsaClientKeyExchangeMessage.class, name = "PskRsaClientKeyExchange"),
            @XmlElement(type = PskServerKeyExchangeMessage.class, name = "PskServerKeyExchange"),
            @XmlElement(type = SrpServerKeyExchangeMessage.class, name = "SrpServerKeyExchange"),
            @XmlElement(type = SrpClientKeyExchangeMessage.class, name = "SrpClientKeyExchange"),
            @XmlElement(type = EndOfEarlyDataMessage.class, name = "EndOfEarlyData"),
            @XmlElement(type = EncryptedExtensionsMessage.class, name = "EncryptedExtensions"),
            @XmlElement(type = HelloRetryRequestMessage.class, name = "HelloRetryRequest") })
    protected ProtocolMessage waitTillMessage;

    public ReceiveTillAction() {
        super();
    }

    public ReceiveTillAction(ProtocolMessage waitTillMessage) {
        super();
        this.waitTillMessage = waitTillMessage;
    }

    public ReceiveTillAction(String connectionAliasAlias, ProtocolMessage waitTillMessage) {
        super(connectionAliasAlias);
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving Messages...");
        MessageActionResult result = receiveMessageHelper.receiveMessagesTill(waitTillMessage, tlsContext);
        records = new ArrayList<>(result.getRecordList());
        messages = new ArrayList<>(result.getMessageList());
        setExecuted(true);

        String expected = getReadableString(waitTillMessage);
        LOGGER.debug("Receive message we waited for:" + expected);
        String received = getReadableString(messages);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Messages: " + received);
        } else {
            LOGGER.info("Received Messages (" + getConnectionAlias() + "): " + received);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("WaitTillReceive Action:\n");

        sb.append("Waiting till:");
        if ((waitTillMessage != null)) {
            sb.append(waitTillMessage.toCompactString());

        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n\tActual:");
        if ((messages != null) && (!messages.isEmpty())) {
            for (ProtocolMessage message : messages) {
                sb.append(message.toCompactString());
                sb.append(", ");
            }
        } else {
            sb.append(" (no messages set)");
        }
        sb.append("\n");
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        StringBuilder sb = new StringBuilder(super.toCompactString());
        if (waitTillMessage != null) {
            sb.append(" (");
            sb.append(waitTillMessage.toCompactString());
            if (sb.lastIndexOf(",") > 0) {
                sb.deleteCharAt(sb.lastIndexOf(","));
            }
            sb.append(")");
        } else {
            sb.append(" (no messages set)");
        }
        return sb.toString();
    }

    @Override
    public boolean executedAsPlanned() {
        if (messages == null) {
            return false;
        }

        for (ProtocolMessage message : messages) {
            if (message.getClass().equals(waitTillMessage.getClass())) {
                return true;
            }
        }

        return false;
    }

    public ProtocolMessage getWaitTillMessage() {
        return waitTillMessage;
    }

    void setReceivedMessages(List<ProtocolMessage> receivedMessages) {
        this.messages = receivedMessages;
    }

    void setReceivedRecords(List<AbstractRecord> receivedRecords) {
        this.records = receivedRecords;
    }

    public void setWaitTillMessage(ProtocolMessage waitTillMessage) {
        this.waitTillMessage = waitTillMessage;
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<AbstractRecord> getReceivedRecords() {
        return records;
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.waitTillMessage);
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);

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
        final ReceiveTillAction other = (ReceiveTillAction) obj;
        return Objects.equals(this.waitTillMessage, other.waitTillMessage);
    }

    @Override
    public void normalize() {
        super.normalize();
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
    }

    @Override
    public void filter() {
        super.filter();
    }

    @Override
    public void filter(TlsAction defaultCon) {
        super.filter(defaultCon);
    }
}
