/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.SpecificContainerLayerConfiguration;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.util.LinkedList;

public abstract class MessageAction extends ConnectionBoundAction {

    public enum MessageActionDirection {
        SENDING,
        RECEIVING
    }

    @XmlElementWrapper
    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
        @XmlElement(type = CertificateMessage.class, name = "Certificate"),
        @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
        @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
        @XmlElement(type = CertificateStatusMessage.class, name = "CertificateStatus"),
        @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
        @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
        @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
        @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
        @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
        @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
        @XmlElement(type = EmptyClientKeyExchangeMessage.class, name = "EmptyClientKeyExchange"),
        @XmlElement(type = PskClientKeyExchangeMessage.class, name = "PSKClientKeyExchange"),
        @XmlElement(type = PWDServerKeyExchangeMessage.class, name = "PWDServerKeyExchange"),
        @XmlElement(type = PWDClientKeyExchangeMessage.class, name = "PWDClientKeyExchange"),
        @XmlElement(type = FinishedMessage.class, name = "Finished"),
        @XmlElement(type = RSAServerKeyExchangeMessage.class, name = "RSAServerKeyExchange"),
        @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
        @XmlElement(type = GOSTClientKeyExchangeMessage.class, name = "GOSTClientKeyExchange"),
        @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
        @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
        @XmlElement(type = AlertMessage.class, name = "Alert"),
        @XmlElement(type = NewSessionTicketMessage.class, name = "NewSessionTicket"),
        @XmlElement(type = KeyUpdateMessage.class, name = "KeyUpdate"),
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
        @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsHandshakeMessageFragment") })
    protected List<ProtocolMessage> messages = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record") })
    protected List<Record> records = new ArrayList<>();

    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = DtlsHandshakeMessageFragment.class, name = "DtlsFragment") })
    protected List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

    public MessageAction() {
    }

    public MessageAction(List<ProtocolMessage> messages) {
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(ProtocolMessage... messages) {
        this.messages = new ArrayList<>(Arrays.asList(messages));
    }

    public MessageAction(String connectionAlias) {
        super(connectionAlias);
    }

    public MessageAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias);
        this.messages = new ArrayList<>(messages);
    }

    public MessageAction(String connectionAlias, ProtocolMessage... messages) {
        this(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
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

    public List<Record> getRecords() {
        return records;
    }

    public void setRecords(List<Record> records) {
        this.records = records;
    }

    public void setRecords(Record... records) {
        this.records = new ArrayList<>(Arrays.asList(records));
    }

    public List<DtlsHandshakeMessageFragment> getFragments() {
        return fragments;
    }

    public void setFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    public void setFragments(DtlsHandshakeMessageFragment... fragments) {
        this.fragments = new ArrayList<>(Arrays.asList(fragments));
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
        if (fragments == null || fragments.isEmpty()) {
            fragments = null;
        }
    }

    private void initEmptyLists() {
        if (messages == null) {
            messages = new ArrayList<>();
        }
        if (records == null) {
            records = new ArrayList<>();
        }
        if (fragments == null) {
            fragments = new ArrayList<>();
        }
    }

    public abstract MessageActionDirection getMessageDirection();

    protected void send(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToSend, List<Record> recordsToSend)
        throws IOException {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
        List<LayerProcessingResult> processingResult = layerStack.sendData(layerConfigurationList);
        messages = new ArrayList<>(processingResult.get(0).getUsedContainers()); // TODO Automatically get correct index
                                                                                 // in result
        records = new ArrayList<>(processingResult.get(1).getUsedContainers()); // TODO Automatically get correct index
                                                                                // in result
    }

    protected void receive(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToReceive,
        List<Record> recordsToReceive) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToReceive));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToReceive));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
        List<LayerProcessingResult> processingResult;
        try {
            processingResult = layerStack.receiveData(layerConfigurationList);
            messages = new ArrayList<>(processingResult.get(0).getUsedContainers()); // TODO Automatically get correct
                                                                                     // index in result
            records = new ArrayList<>(processingResult.get(1).getUsedContainers()); // TODO Automatically get correct
                                                                                    // index in result
        } catch (IOException ex) {
            LOGGER.warn("Received an IOException");
        }
    }

    protected void receiveTill(TlsContext tlsContext, List<ProtocolMessage> protocolMessagesToSend,
        List<Record> recordsToSend) {
        LayerStack layerStack = tlsContext.getLayerStack();
        List<LayerConfiguration> layerConfigurationList = new LinkedList<>();
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(protocolMessagesToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration(recordsToSend));
        layerConfigurationList.add(new SpecificContainerLayerConfiguration((List) null));
        List<LayerProcessingResult> processingResult;
        try {
            processingResult = layerStack.receiveData(layerConfigurationList);
            messages = new ArrayList<>(processingResult.get(0).getUsedContainers()); // TODO Automatically get correct
                                                                                     // index in result
            records = new ArrayList<>(processingResult.get(1).getUsedContainers()); // TODO Automatically get correct
                                                                                    // index in result
        } catch (IOException ex) {
            LOGGER.warn("Received an IOException");
        }
    }

}
