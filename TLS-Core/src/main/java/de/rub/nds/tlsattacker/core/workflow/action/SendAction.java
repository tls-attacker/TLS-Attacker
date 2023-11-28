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
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** todo print configured records */
@XmlRootElement(name = "Send")
public class SendAction extends CommonSendAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<ProtocolMessage> configuredMessages = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<HttpMessage> configuredHttpMessages = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicFrame> configuredQuicFrames = new ArrayList<>();

    @HoldsModifiableVariable @XmlElementWrapper @XmlElementRef
    protected List<QuicPacket> configuredQuicPackets = new ArrayList<>();

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
        this.setHttpMessages(new ArrayList<>(Arrays.asList(httpMessage)));
    }

    public SendAction(ProtocolMessage... messages) {
        this(new ArrayList<>(Arrays.asList(messages)));
    }

    public SendAction(String connectionAlias) {
        super(connectionAlias);
    }

    public SendAction(String connectionAlias, List<ProtocolMessage> messages) {
        super(connectionAlias, messages);
    }

    public SendAction(String connectionAlias, ProtocolMessage... messages) {
        super(connectionAlias, new ArrayList<>(Arrays.asList(messages)));
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        String sending =
                getReadableStringFromContainerList(messages, httpMessages, quicPackets, quicFrames);
        if (hasDefaultAlias()) {
            LOGGER.info("Sending messages: {}", sending);
        } else {
            LOGGER.info("Sending messages ({}): {}", connectionAlias, sending);
        }

        try {
            send(tlsContext, messages, fragments, records, quicFrames, quicPackets, httpMessages);
            setExecuted(true);
        } catch (IOException e) {
            if (!getActionOptions().contains(ActionOption.MAY_FAIL)) {
                tlsContext.setReceivedTransportHandlerException(true);
                LOGGER.debug(e);
            }
            setExecuted(getActionOptions().contains(ActionOption.MAY_FAIL));
        }
    }

    @Override
    public String toString() {
        return "SendAction: "
                + (isExecuted() ? "\n" : "(not executed)\n")
                + "\tMessages: "
                + getReadableStringFromContainerList(
                        messages, httpMessages, quicPackets, quicFrames);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString()
                + getReadableStringFromContainerList(
                        messages, httpMessages, quicPackets, quicFrames);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void setRecords(List<Record> records) {
        this.records = records;
    }

    @Override
    public void setFragments(List<DtlsHandshakeMessageFragment> fragments) {
        this.fragments = fragments;
    }

    @Override
    public void reset() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        if (messages != null) {
            for (ProtocolMessage message : messages) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }
        if (getRecords() != null) {
            for (Record record : getRecords()) {
                holders.addAll(record.getAllModifiableVariableHolders());
            }
        }
        if (getFragments() != null) {
            for (DtlsHandshakeMessageFragment fragment : getFragments()) {
                holders.addAll(fragment.getAllModifiableVariableHolders());
            }
        }
        if (getHttpMessages() != null) {
            for (HttpMessage msg : getHttpMessages()) {
                holders.addAll(msg.getAllModifiableVariableHolders());
            }
        }
        if (getQuicFrames() != null) {
            for (QuicFrame frames : getQuicFrames()) {
                holders.addAll(frames.getAllModifiableVariableHolders());
            }
        }
        if (getQuicPackets() != null) {
            for (QuicPacket packets : getQuicPackets()) {
                holders.addAll(packets.getAllModifiableVariableHolders());
            }
        }

        for (ModifiableVariableHolder holder : holders) {
            holder.reset();
        }
        setExecuted(null);
    }

    @Override
    public List<ProtocolMessageType> getGoingToSendProtocolMessageTypes() {
        List<ProtocolMessageType> protocolMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : messages) {
            protocolMessageTypes.add(msg.getProtocolMessageType());
        }
        return protocolMessageTypes;
    }

    @Override
    public List<HandshakeMessageType> getGoingToSendHandshakeMessageTypes() {
        List<HandshakeMessageType> handshakeMessageTypes = new ArrayList<>();
        for (ProtocolMessage msg : messages) {
            if (msg instanceof HandshakeMessage) {
                handshakeMessageTypes.add(((HandshakeMessage) msg).getHandshakeMessageType());
            }
        }
        return handshakeMessageTypes;
    }
}
