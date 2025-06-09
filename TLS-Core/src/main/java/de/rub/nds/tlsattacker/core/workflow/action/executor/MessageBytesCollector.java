/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;

public class MessageBytesCollector {

    private SilentByteArrayOutputStream recordBytesStream;

    private SilentByteArrayOutputStream protocolMessageBytesStream;

    public MessageBytesCollector() {
        recordBytesStream = new SilentByteArrayOutputStream();
        protocolMessageBytesStream = new SilentByteArrayOutputStream();
    }

    public byte[] getRecordBytes() {
        return recordBytesStream.toByteArray();
    }

    public byte[] getProtocolMessageBytesStream() {
        return protocolMessageBytesStream.toByteArray();
    }

    public void appendRecordBytes(byte[] recordBytes) {
        this.recordBytesStream.write(recordBytes);
    }

    public void appendProtocolMessageBytes(byte[] protocolMessageBytes) {
        protocolMessageBytesStream.write(protocolMessageBytes);
    }

    public void flushRecordBytes() {
        recordBytesStream = new SilentByteArrayOutputStream();
    }

    public void flushProtocolMessageBytes() {
        protocolMessageBytesStream = new SilentByteArrayOutputStream();
    }
}
