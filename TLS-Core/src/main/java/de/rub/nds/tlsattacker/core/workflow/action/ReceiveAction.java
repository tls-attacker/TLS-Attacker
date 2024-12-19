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
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.container.ActionHelperUtil;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@XmlRootElement(name = "Receive")
public class ReceiveAction extends CommonReceiveAction implements StaticReceivingAction {

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> expectedMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<Record> expectedRecords;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<DtlsHandshakeMessageFragment> expectedDtlsFragments;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage> expectedHttpMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<SmtpMessage> expectedSmtpMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<Pop3Message> expectedPop3Messages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> expectedQuicFrames;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> expectedQuicPackets;

    public ReceiveAction() {
        super();
    }

    public ReceiveAction(
            Set<ActionOption> actionOptions,
            List<ProtocolMessage> expectedMessages,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> quicPackets) {
        super();
        setActionOptions(actionOptions);
        this.expectedMessages = expectedMessages;
        this.expectedQuicFrames = expectedQuicFrames;
        this.expectedQuicPackets = quicPackets;
    }

    public ReceiveAction(List<ProtocolMessage> expectedMessages) {
        super();
        this.expectedMessages = expectedMessages;
    }

    public ReceiveAction(ProtocolMessage... expectedMessages) {
        super();
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    public ReceiveAction(QuicFrame... expectedQuicFrames) {
        super();
        this.expectedQuicFrames = new ArrayList<>(Arrays.asList(expectedQuicFrames));
    }

    public ReceiveAction(QuicPacket... expectedQuicPackets) {
        super();
        this.expectedQuicPackets = new ArrayList<>(Arrays.asList(expectedQuicPackets));
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
            ActionOption actionOption,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        this.expectedQuicFrames = expectedQuicFrames;
        this.expectedQuicPackets = expectedQuicPackets;
        if (actionOption != null) {
            this.addActionOption(actionOption);
        }
    }

    public ReceiveAction(
            Set<ActionOption> actionOptions,
            List<QuicFrame> expectedQuicFrames,
            List<QuicPacket> expectedQuicPackets) {
        this.expectedQuicFrames = expectedQuicFrames;
        this.expectedQuicPackets = expectedQuicPackets;
        this.setActionOptions(actionOptions);
    }

    public ReceiveAction(
            List<ProtocolMessage> expectedMessages, List<HttpMessage> expectedHttpMessages) {
        this(expectedMessages);
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public ReceiveAction(HttpMessage... expectedHttpMessages) {
        this.expectedHttpMessages = new ArrayList<>(Arrays.asList(expectedHttpMessages));
    }

    public ReceiveAction(SmtpMessage... expectedSmtpMessages) {
        this.expectedSmtpMessages = new ArrayList<>(Arrays.asList(expectedSmtpMessages));
    }

    public ReceiveAction(String connectionAlias, SmtpMessage... expectedSmtpMessages) {
        super(connectionAlias);
        this.expectedSmtpMessages = new ArrayList<>(Arrays.asList(expectedSmtpMessages));
    }

    public ReceiveAction(Pop3Message... expectedPop3Messages) {
        this.expectedPop3Messages = new ArrayList<>(Arrays.asList(expectedPop3Messages));
    }

    public ReceiveAction(String connectionAlias, Pop3Message... expectedPop3Messages) {
        super(connectionAlias);
        this.expectedPop3Messages = new ArrayList<>(Arrays.asList(expectedPop3Messages));
    }

    public ReceiveAction(Set<ActionOption> myActionOptions, List<ProtocolMessage> messages) {
        this(messages);
        setActionOptions(myActionOptions);
    }

    public ReceiveAction(Set<ActionOption> actionOptions, ProtocolMessage... messages) {
        this(actionOptions, new ArrayList<>(Arrays.asList(messages)));
    }

    public ReceiveAction(ActionOption actionOption, List<ProtocolMessage> messages) {
        this(messages);
        setActionOptions(Set.of(actionOption));
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
    public String toString() {
        String string =
                getClass().getSimpleName()
                        + ": "
                        + (isExecuted() ? "\n" : "(not executed)\n")
                        + "\tExpected: "
                        + LogPrinter.toHumanReadableMultiLineContainerListArray(
                                getExpectedDataContainerLists());
        if (isExecuted()) {
            string +=
                    "\n\tActual: "
                            + LogPrinter.toHumanReadableMultiLine(getLayerStackProcessingResult());
        }
        return string;
    }

    @Override
    public String toCompactString() {
        return LogPrinter.toHumanReadableMultiLineContainerListArray(
                getExpectedDataContainerLists());
    }

    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
    }

    public void setExpectedMessages(List<ProtocolMessage> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage... expectedMessages) {
        this.expectedMessages = new ArrayList<>(Arrays.asList(expectedMessages));
    }

    public List<HttpMessage> getExpectedHttpMessages() {
        return expectedHttpMessages;
    }

    public void setExpectedHttpMessages(List<HttpMessage> expectedHttpMessages) {
        this.expectedHttpMessages = expectedHttpMessages;
    }

    public List<SmtpMessage> getExpectedSmtpMessages() {
        return expectedSmtpMessages;
    }

    public void setExpectedSmtpMessages(List<SmtpMessage> expectedSmtpMessages) {
        this.expectedSmtpMessages = expectedSmtpMessages;
    }

    public List<Pop3Message> getExpectedPop3Messages() {
        return expectedPop3Messages;
    }

    public void setExpectedPop3Messages(List<Pop3Message> expectedPop3Messages) {
        this.expectedPop3Messages = expectedPop3Messages;
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

    public List<Record> getExpectedRecords() {
        return expectedRecords;
    }

    public void setExpectedRecords(List<Record> expectedRecords) {
        this.expectedRecords = expectedRecords;
    }

    public List<DtlsHandshakeMessageFragment> getExpectedDtlsFragments() {
        return expectedDtlsFragments;
    }

    public void setExpectedDtlsFragments(List<DtlsHandshakeMessageFragment> expectedDtlsFragments) {
        this.expectedDtlsFragments = expectedDtlsFragments;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        return ActionHelperUtil.createReceiveLayerConfiguration(
                tlsContext,
                getActionOptions(),
                expectedMessages,
                expectedDtlsFragments,
                expectedRecords,
                expectedQuicFrames,
                expectedQuicPackets,
                expectedHttpMessages,
                expectedSmtpMessages,
                expectedPop3Messages);
    }

    @Override
    public List<List<DataContainer<?>>> getExpectedDataContainerLists() {
        List<List<DataContainer<?>>> dataContainerLists = new LinkedList<>();
        if (expectedHttpMessages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedHttpMessages);
        }
        if (expectedSmtpMessages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedSmtpMessages);
        }
        if (expectedPop3Messages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedPop3Messages);
        }
        if (expectedMessages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedMessages);
        }
        if (expectedDtlsFragments != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedDtlsFragments);
        }
        if (expectedRecords != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedRecords);
        }
        if (expectedQuicFrames != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedQuicFrames);
        }
        if (expectedQuicPackets != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) expectedQuicPackets);
        }
        return dataContainerLists;
    }
}
