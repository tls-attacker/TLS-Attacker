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
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlTransient;

public abstract class MessageAction extends ConnectionBoundAction {

    @XmlElementWrapper
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
            @XmlElement(type = GOSTClientKeyExchangeMessage.class, name = "GOSTClientKeyExchange"),
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
    protected List<ProtocolMessage> messages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
            @XmlElement(type = BlobRecord.class, name = "BlobRecord") })
    protected List<AbstractRecord> records = new ArrayList<>();

    @XmlTransient
    protected ReceiveMessageHelper receiveMessageHelper;

    @XmlTransient
    protected SendMessageHelper sendMessageHelper;

    public MessageAction() {
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(List<ProtocolMessage> messages) {
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(ProtocolMessage... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
        receiveMessageHelper = new ReceiveMessageHelper();
        sendMessageHelper = new SendMessageHelper();
    }

    public MessageAction(String connectionAlias, ProtocolMessage... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    public void setReceiveMessageHelper(ReceiveMessageHelper receiveMessageHelper) {
        this.receiveMessageHelper = receiveMessageHelper;
    }

    public void setSendMessageHelper(SendMessageHelper sendMessageHelper) {
        this.sendMessageHelper = sendMessageHelper;
    }

    public String getReadableString(ProtocolMessage... messages) {
        return getReadableString(Arrays.asList(messages));
    }

    public String getReadableString(List<ProtocolMessage> messages) {
        return getReadableString(messages, false);
    }

    public String getReadableString(List<ProtocolMessage> messages, Boolean verbose) {
        StringBuilder builder = new StringBuilder();
        if (messages == null) {
            return builder.toString();
        }
        for (ProtocolMessage message : messages) {
            if (verbose) {
                builder.append(message.toString());
            } else {
                builder.append(message.toCompactString());
            }
            if (!message.isRequired()) {
                builder.append("*");
            }
            builder.append(", ");
        }
        return builder.toString();
    }

    public List<ProtocolMessage> getMessages() {
        return messages;
    }

    public void setMessages(List<ProtocolMessage> messages) {
        this.messages = messages;
    }

    public void setMessages(ProtocolMessage... messages) {
        this.messages = new ArrayList(Arrays.asList(messages));
    }

    public List<AbstractRecord> getRecords() {
        return records;
    }

    public void setRecords(List<AbstractRecord> records) {
        this.records = records;
    }

    public void setRecords(AbstractRecord... records) {
        this.records = new ArrayList<>(Arrays.asList(records));
    }

    public void clearRecords() {
        this.records = null;
    }

    @Override
    public void normalize() {
        super.normalize();
        initEmptyLists();
    }

    @Override
    public void normalize(TlsAction defaultAction) {
        super.normalize(defaultAction);
        initEmptyLists();
    }

    @Override
    public void filter() {
        super.filter();
        stripEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultAction) {
        super.filter(defaultAction);
        stripEmptyLists();
    }

    private void stripEmptyLists() {
        if (messages == null || messages.isEmpty()) {
            messages = null;
        }
        if (records == null || records.isEmpty()) {
            records = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
        if (records == null) {
            records = new ArrayList<>();
        }
    }

}
