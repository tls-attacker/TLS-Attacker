/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class SendAction extends MessageAction implements SendingAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public SendAction() {
        super();
    }

    public SendAction(
            List<ProtocolMessage> messages,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        super(messages, quicFrames, quicPackets);
    }

    public SendAction(
            ActionOption option,
            List<ProtocolMessage> messages,
            List<QuicFrame> quicFrames,
            List<QuicPacket> quicPackets) {
        super(messages, quicFrames, quicPackets);
        if (option != null) {
            this.addActionOption(option);
        }
    }

    public SendAction(ActionOption option, List<ProtocolMessage> messages) {
        super(messages);
        if (option != null) {
            this.addActionOption(option);
        }
    }

    public SendAction(ActionOption option, ProtocolMessage... messages) {
        this(option, new ArrayList<>(Arrays.asList(messages)));
    }

    public SendAction(List<ProtocolMessage> messages) {
        super(messages);
    }

    public SendAction(QuicPacket... quicPackets) {
        super(quicPackets);
    }

    public SendAction(QuicFrame... quicFrames) {
        super(quicFrames);
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
            LOGGER.info("Sending messages: " + sending);
        } else {
            LOGGER.info("Sending messages (" + connectionAlias + "): " + sending);
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
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }

    @Override
    public List<QuicPacket> getSendQuicPackets() {
        return quicPackets;
    }

    @Override
    public List<QuicFrame> getSendQuicFrames() {
        return quicFrames;
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
