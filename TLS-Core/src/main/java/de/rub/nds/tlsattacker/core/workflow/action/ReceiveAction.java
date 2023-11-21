/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "Receive")
public class ReceiveAction extends CommonReceiveAction implements ReceivingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> expectedMessages = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage> expectedHttpMessages = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> expectedQuicFrames = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> expectedQuicPackets = new ArrayList<>();

    public ReceiveAction() {
        super();
    }

    public ReceiveAction(
            List<ProtocolMessage> messages,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        super(messages, quicFrames, quicPackets);
    }

    public ReceiveAction(
            Set<ActionOption> actionOptions,
            List<ProtocolMessage> messages,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        super(messages, quicFrames, quicPackets);
        setActionOptions(actionOptions);
    }

    public ReceiveAction(List<ProtocolMessage> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(ProtocolMessage... expectedMessages) {
        super();
        this.expectedMessages = new ArrayList(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(QuicFrame... expectedQuicFrames) {
        super();
        this.expectedQuicFrames = new ArrayList(Arrays.asList(expectedQuicFrames));
    }

    public ReceiveAction(QuicPacket... expectedQuicPackets) {
        super();
        this.expectedQuicPackets = new ArrayList(Arrays.asList(expectedQuicPackets));
    }

    public ReceiveAction(ActionOption actionOption, QuicFrame... expectedQuicFrames) {
        this(expectedQuicFrames);
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveAction(ActionOption actionOption, QuicPacket... expectedQuicPackets) {
        this(expectedQuicPackets);
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveAction(
            List<ProtocolMessage> expectedMessages, List<HttpMessage> expectedHttpMessages) {
        this(expectedMessages);
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public ReceiveAction(HttpMessage... expectedHttpMessages) {
        this.expectedHttpMessages = new ArrayList(Arrays.asList(expectedHttpMessages));
    }

    public ReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        this(messages);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        this(actionOptions, new ArrayList(Arrays.asList(messages)));
    }

    public ReceiveAction(ActionOption actionOption, List<ProtocolMessage> messages) {
        this(messages);
        HashSet myActionOptions = new HashSet();
        myActionOptions.add(actionOption);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(ActionOption actionOption, ProtocolMessage... messages) {
        this(actionOption, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ReceiveAction(String connectionAliasAlias, List<ProtocolMessage> messages) {
        super(connectionAliasAlias);
        this.expectedMessages = messages;
    }

    public ReceiveAction(String connectionAliasAlias, ProtocolMessage... messages) {
        this(connectionAliasAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LOGGER.debug("Receiving...");
        distinctReceive(tlsContext);

        setExecuted(true);

        String expected =
                getReadableStringFromContainerList(
                        expectedMessages,
                        expectedHttpMessages,
                        expectedQuicPackets,
                        expectedQuicFrames);
        LOGGER.debug("Receive Expected:" + expected);
        String received =
                getReadableStringFromContainerList(messages, httpMessages, quicPackets, quicFrames);
        if (hasDefaultAlias()) {
            LOGGER.info("Received Containers: " + received);
        } else {
            LOGGER.info("Received Containers (" + getConnectionAlias() + "): " + received);
        }
    }

    @Override
    public String toString() {
        String string =
                getClass().getSimpleName()
                        + ": "
                        + (isExecuted() ? "\n" : "(not executed)\n")
                        + "\tExpected: "
                        + getReadableStringFromContainerList(
                                expectedMessages,
                                expectedHttpMessages,
                                expectedQuicPackets,
                                expectedQuicFrames);
        if (isExecuted()) {
            string +=
                    "\n\tActual:"
                            + getReadableStringFromContainerList(
                                    messages, httpMessages, quicPackets, quicFrames);
        }
        return string;
    }

    @Override
    public String toCompactString() {
        return super.toCompactString()
                + getReadableStringFromContainerList(
                        expectedMessages,
                        expectedHttpMessages,
                        expectedQuicPackets,
                        expectedQuicFrames);
    }

    @Override
    public boolean executedAsPlanned() {
        if (getLayerStackProcessingResult() != null) {
            for (LayerProcessingResult result :
                    getLayerStackProcessingResult().getLayerProcessingResultList()) {
                if (!result.isExecutedAsPlanned()) {
                    LOGGER.error(
                            "ReceiveAction failed: Layer {}, did not execute as planned",
                            result.getLayerType());
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    @Override
    public void reset() {
        messages = null;
        records = null;
        fragments = null;
        quicFrames = null;
        quicPackets = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = super.hashCode();
        hash = 67 * hash + Objects.hashCode(this.expectedMessages);
        hash = 67 * hash + Objects.hashCode(this.messages);
        hash = 67 * hash + Objects.hashCode(this.records);
        hash = 67 * hash + Objects.hashCode(this.fragments);
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
        final ReceiveAction other = (ReceiveAction) obj;
        if (!Objects.equals(this.expectedMessages, other.expectedMessages)) {
            return false;
        }
        if (!Objects.equals(this.messages, other.messages)) {
            return false;
        }
        if (!Objects.equals(this.records, other.records)) {
            return false;
        }
        if (!Objects.equals(this.fragments, other.fragments)) {
            return false;
        }
        if (!Objects.equals(this.quicFrames, other.quicFrames)) {
            return false;
        }
        if (!Objects.equals(this.quicPackets, other.quicPackets)) {
            return false;
        }
        return super.equals(obj);
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
        filterEmptyLists();
    }

    @Override
    public void filter(TlsAction defaultCon) {
        super.filter(defaultCon);
        filterEmptyLists();
    }

    private void filterEmptyLists() {
        if (expectedMessages == null || expectedMessages.isEmpty()) {
            expectedMessages = null;
        }
        if (expectedHttpMessages == null || expectedHttpMessages.isEmpty()) {
            expectedHttpMessages = null;
        }
        if (expectedQuicFrames == null || expectedQuicFrames.isEmpty()) {
            expectedQuicFrames = null;
        }
        if (expectedQuicPackets == null || expectedQuicPackets.isEmpty()) {
            expectedQuicPackets = null;
        }
    }

    private void initEmptyLists() {
        if (expectedMessages == null) {
            expectedMessages = new ArrayList<>();
        }
        if (expectedHttpMessages == null) {
            expectedHttpMessages = new ArrayList<>();
        }
        if (expectedQuicFrames == null) {
            expectedQuicFrames = new ArrayList<>();
        }
        if (expectedQuicPackets == null) {
            expectedQuicPackets = new ArrayList<>();
        }
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : expectedMessages) {
            protocolMessageTypes.add(msg.getProtocolMessageType());
        }
        return protocolMessageTypes;
    }

    @Override
    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        List<HandshakeMessageType> handshakeMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : expectedMessages) {
            if (msg instanceof HandshakeMessage) {
                handshakeMessageTypes.add(((HandshakeMessage) msg).getHandshakeMessageType());
            }
        }
        return handshakeMessageTypes;
    }

    protected void distinctReceive(TlsContext tlsContext) {
        receive(
                tlsContext,
                expectedMessages,
                fragments,
                records,
                expectedQuicFrames,
                expectedQuicPackets,
                httpMessages);
    }

    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
    }

    public void setExpectedMessages(List<ProtocolMessage> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage... expectedMessages) {
        this.expectedMessages = new ArrayList(Arrays.asList(expectedMessages));
    }

    public List<HttpMessage> getExpectedHttpMessages() {
        return expectedHttpMessages;
    }

    public void setExpectedHttpMessages(List<HttpMessage> expectedHttpMessages) {
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public List<QuicFrame> getExpectedQuicFrames() {
        return expectedQuicFrames;
    }

    public void setExpectedQuicFrames(List<QuicFrame> expectedQuicFrames) {
        this.expectedQuicFrames = expectedQuicFrames;
    }

    public List<QuicPacket> getExpectedQuicPackets() {
        return expectedQuicPackets;
    }

    public void setExpectedQuicPackets(List<QuicPacket> expectedQuicPackets) {
        this.expectedQuicPackets = expectedQuicPackets;
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return getMessages();
    }

    @Override
    public List<Record> getReceivedRecords() {
        return getRecords();
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return getFragments();
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return getHttpMessages();
    }

    public void setReceivedMessages(List<ProtocolMessage> messages) {
        setMessages(messages);
    }

    public void setReceivedRecords(List<Record> records) {
        setRecords(records);
    }

    public Set<String> getAllReceivingAliases() {
        return new HashSet<>(Collections.singleton(connectionAlias));
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }
}
