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
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.printer.LogPrinter;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
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

/** todo print configured records */
@XmlRootElement(name = "Send")
public class SendAction extends CommonSendAction implements StaticSendingAction {

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> configuredMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<DtlsHandshakeMessageFragment> configuredDtlsHandshakeMessageFragments;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<Record> configuredRecords;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage> configuredHttpMessages;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> configuredQuicFrames;

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> configuredQuicPackets;

    public SendAction() {}

    public SendAction(
            List<ProtocolMessage> configuredMessages,
            List<QuicFrame> configuredQuicFrames,
            List<QuicPacket> configuredQuicPackets) {
        this.configuredMessages = configuredMessages;
        this.configuredQuicFrames = configuredQuicFrames;
        this.configuredQuicPackets = configuredQuicPackets;
    }

    public SendAction(
            ActionOption option,
            List<ProtocolMessage> configuredMessages,
            List<QuicFrame> configuredQuicFrames,
            List<QuicPacket> configuredQuicPackets) {
        this(configuredMessages, configuredQuicFrames, configuredQuicPackets);
        if (option != null) {
            this.addActionOption(option);
        }
    }

    public SendAction(ActionOption option, List<ProtocolMessage> configuredMessages) {
        this(configuredMessages);
        if (option != null) {
            this.addActionOption(option);
        }
    }

    public SendAction(ActionOption option, ProtocolMessage... configuredMessages) {
        this(option, new ArrayList<>(Arrays.asList(configuredMessages)));
    }

    public SendAction(List<ProtocolMessage> configuredMessages) {
        this.configuredMessages = configuredMessages;
    }

    public SendAction(QuicPacket... configuredQuicPackets) {
        this.configuredQuicPackets = new ArrayList<>(Arrays.asList(configuredQuicPackets));
    }

    public SendAction(QuicFrame... configuredQuicFrames) {
        this.configuredQuicFrames = new ArrayList<>(Arrays.asList(configuredQuicFrames));
    }

    public SendAction(HttpMessage... httpMessage) {
        this.configuredHttpMessages = new ArrayList<>(Arrays.asList(httpMessage));
    }

    public SendAction(ProtocolMessage... messages) {
        this(new ArrayList<>(Arrays.asList(messages)));
    }

    public SendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public SendAction(String connectionAlias, List<ProtocolMessage> configuredMessages) {
        super(connectionAlias);
        this.configuredMessages = configuredMessages;
    }

    public SendAction(String connectionAlias, ProtocolMessage... configuredMessages) {
        this(connectionAlias);
        this.configuredMessages = new ArrayList<>(Arrays.asList(configuredMessages));
    }

    public List<ProtocolMessage> getConfiguredMessages() {
        return configuredMessages;
    }

    public void setConfiguredMessages(List<ProtocolMessage> configuredMessages) {
        this.configuredMessages = configuredMessages;
    }

    public void setConfiguredMessages(ProtocolMessage... configuredMessages) {
        this.configuredMessages = new ArrayList<>(Arrays.asList(configuredMessages));
    }

    public List<DtlsHandshakeMessageFragment> getConfiguredDtlsHandshakeMessageFragments() {
        return configuredDtlsHandshakeMessageFragments;
    }

    public void setConfiguredDtlsHandshakeMessageFragments(
            List<DtlsHandshakeMessageFragment> configuredDtlsHandshakeMessageFragment) {
        this.configuredDtlsHandshakeMessageFragments = configuredDtlsHandshakeMessageFragment;
    }

    public List<Record> getConfiguredRecords() {
        return configuredRecords;
    }

    public void setConfiguredRecords(List<Record> configuredRecords) {
        this.configuredRecords = configuredRecords;
    }

    public List<HttpMessage> getConfiguredHttpMessages() {
        return configuredHttpMessages;
    }

    public void setConfiguredHttpMessages(List<HttpMessage> configuredHttpMessages) {
        this.configuredHttpMessages = configuredHttpMessages;
    }

    public List<QuicFrame> getConfiguredQuicFrames() {
        return configuredQuicFrames;
    }

    public void setConfiguredQuicFrames(QuicFrame... configuredQuicFrames) {
        this.configuredQuicFrames = new ArrayList<>(Arrays.asList(configuredQuicFrames));
    }

    public void setConfiguredQuicFrames(List<QuicFrame> configuredQuicFrames) {
        this.configuredQuicFrames = configuredQuicFrames;
    }

    public List<QuicPacket> getConfiguredQuicPackets() {
        return configuredQuicPackets;
    }

    public void setConfiguredQuicPackets(QuicPacket... configuredQuicPackets) {
        this.configuredQuicPackets = new ArrayList<>(Arrays.asList(configuredQuicPackets));
    }

    public void setConfiguredQuicPackets(List<QuicPacket> configuredQuicPackets) {
        this.configuredQuicPackets = configuredQuicPackets;
    }

    @Override
    public String toString() {
        return "SendAction: "
                + (isExecuted() ? "\n" : "(not executed)\n")
                + "\tMessages: "
                + LogPrinter.toHumanReadableMultiLineContainerListArray(
                        getConfiguredDataContainerLists());
    }

    @Override
    public String toCompactString() {
        return super.toCompactString()
                + LogPrinter.toHumanReadableMultiLineContainerListArray(
                        getConfiguredDataContainerLists());
    }

    @Override
    public void reset() {
        super.reset();
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (configuredMessages != null) {
            for (ProtocolMessage message : configuredMessages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        if (configuredRecords != null) {
            for (Record record : configuredRecords) {
                holders.addAll(record.getAllModifiableVariableHolders());
            }
        }
        if (configuredDtlsHandshakeMessageFragments != null) {
            for (DtlsHandshakeMessageFragment fragment : configuredDtlsHandshakeMessageFragments) {
                holders.addAll(fragment.getAllModifiableVariableHolders());
            }
        }
        if (configuredHttpMessages != null) {
            for (HttpMessage msg : configuredHttpMessages) {
                holders.addAll(msg.getAllModifiableVariableHolders());
            }
        }
        if (configuredQuicFrames != null) {
            for (QuicFrame frames : configuredQuicFrames) {
                holders.addAll(frames.getAllModifiableVariableHolders());
            }
        }
        if (configuredQuicPackets != null) {
            for (QuicPacket packets : configuredQuicPackets) {
                holders.addAll(packets.getAllModifiableVariableHolders());
            }
        }

        for (ModifiableVariableHolder holder : holders) {
            holder.reset();
        }
    }

    public List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : configuredMessages) {
            protocolMessageTypes.add(msg.getProtocolMessageType());
        }
        return protocolMessageTypes;
    }

    public List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        List<HandshakeMessageType> handshakeMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : configuredMessages) {
            if (msg instanceof HandshakeMessage) {
                handshakeMessageTypes.add(((HandshakeMessage) msg).getHandshakeMessageType());
            }
        }
        return handshakeMessageTypes;
    }

    @Override
    protected List<LayerConfiguration<?>> createLayerConfiguration(State state) {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());
        List<LayerConfiguration<?>> configurationList = new LinkedList<>();
        if (getConfiguredRecords() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.RECORD, getConfiguredMessages()));
        }
        if (getConfiguredMessages() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.SSL2, getConfiguredMessages()));
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.MESSAGE, getConfiguredMessages()));
        }
        if (getConfiguredDtlsHandshakeMessageFragments() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.DTLS_FRAGMENT,
                            getConfiguredDtlsHandshakeMessageFragments()));
        }
        if (getConfiguredHttpMessages() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.HTTP, getConfiguredHttpMessages()));
        }
        if (getConfiguredQuicFrames() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICFRAME, getConfiguredQuicFrames()));
        }
        if (getConfiguredQuicPackets() != null) {
            configurationList.add(
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.QUICPACKET, getConfiguredQuicPackets()));
        }
        return ActionHelperUtil.sortAndAddOptions(
                tlsContext.getLayerStack(), true, getActionOptions(), configurationList);
    }

    @Override
    public List<List<DataContainer<?>>> getConfiguredDataContainerLists() {
        List<List<DataContainer<?>>> dataContainerLists = new LinkedList<>();
        if (configuredHttpMessages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) configuredHttpMessages);
        }
        if (configuredMessages != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) configuredMessages);
        }
        if (configuredDtlsHandshakeMessageFragments != null) {
            dataContainerLists.add(
                    (List<DataContainer<?>>) (List<?>) configuredDtlsHandshakeMessageFragments);
        }
        if (configuredRecords != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) configuredRecords);
        }
        if (configuredQuicFrames != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) configuredQuicFrames);
        }
        if (configuredQuicPackets != null) {
            dataContainerLists.add((List<DataContainer<?>>) (List<?>) configuredQuicPackets);
        }
        return dataContainerLists;
    }
}
