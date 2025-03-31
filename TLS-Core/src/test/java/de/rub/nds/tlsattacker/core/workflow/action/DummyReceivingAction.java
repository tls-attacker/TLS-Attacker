/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@XmlRootElement
public class DummyReceivingAction extends MessageAction
        implements ReceivingAction, StaticReceivingAction {

    private List<ProtocolMessage> expectedMessages;

    private List<Record> expectedRecords;

    public DummyReceivingAction() {
        super();
    }

    public DummyReceivingAction(List<ProtocolMessage> configuredMessages) {
        super();
        this.expectedMessages = configuredMessages;
    }

    public DummyReceivingAction(ProtocolMessage... configuredMessages) {
        super();
        this.expectedMessages = List.of(configuredMessages);
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return expectedMessages;
    }

    @Override
    public List<Record> getReceivedRecords() {
        return expectedRecords;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedFragments'");
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedHttpMessages'");
    }

    @Override
    public List<Pop3Message> getReceivedPop3Messages() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedPop3Messages'");
    }

    @Override
    public List<SmtpMessage> getReceivedSmtpMessages() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedSmtpMessages'");
    }

    @Override
    public List<QuicFrame> getReceivedQuicFrames() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedQuicFrames'");
    }

    @Override
    public List<QuicPacket> getReceivedQuicPackets() {
        throw new UnsupportedOperationException("Unimplemented method 'getReceivedQuicPackets'");
    }

    @Override
    public Set<String> getAllReceivingAliases() {
        throw new UnsupportedOperationException("Unimplemented method 'getAllReceivingAliases'");
    }

    @Override
    public MessageActionDirection getMessageDirection() {
        return MessageActionDirection.RECEIVING;
    }

    public List<ProtocolMessage> getExpectedMessages() {
        return expectedMessages;
    }

    public void setExpectedMessages(List<ProtocolMessage> expectedMessages) {
        this.expectedMessages = expectedMessages;
    }

    public void setExpectedMessages(ProtocolMessage... expectedMessages) {
        this.expectedMessages = List.of(expectedMessages);
    }

    public List<Record> getExpectedRecords() {
        return expectedRecords;
    }

    public void setExpectedRecords(List<Record> expectedRecords) {
        this.expectedRecords = expectedRecords;
    }

    public void setExpectedRecords(Record... expectedRecords) {
        this.expectedRecords = List.of(expectedRecords);
    }

    @Override
    public void execute(State state) throws ActionExecutionException {}

    @Override
    public boolean executedAsPlanned() {
        return true;
    }

    @Override
    public List<List<DataContainer<?>>> getExpectedDataContainerLists() {
        List<List<DataContainer<?>>> lists = new LinkedList<>();
        if (expectedMessages != null) {
            lists.add((List<DataContainer<?>>) (List<?>) expectedMessages);
        }
        if (expectedRecords != null) {
            lists.add((List<DataContainer<?>>) (List<?>) expectedRecords);
        }
        return lists;
    }
}
