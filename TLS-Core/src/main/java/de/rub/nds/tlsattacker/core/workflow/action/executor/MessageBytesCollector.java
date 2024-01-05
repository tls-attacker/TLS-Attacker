/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action.executor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MessageBytesCollector {

    private ByteArrayOutputStream recordBytesStream;

    private ByteArrayOutputStream protocolMessageBytesStream;

    public MessageBytesCollector() {
        recordBytesStream = new ByteArrayOutputStream();
        protocolMessageBytesStream = new ByteArrayOutputStream();
    }

    public byte[] getRecordBytes() {
        return recordBytesStream.toByteArray();
    }

    public byte[] getProtocolMessageBytesStream() {
        return protocolMessageBytesStream.toByteArray();
    }

    public void appendRecordBytes(byte[] recordBytes) {
        try {
            this.recordBytesStream.write(recordBytes);
        } catch (IOException ex) {
            // TODO
        }
    }

    public void appendProtocolMessageBytes(byte[] protocolMessageBytes) {
        try {
            protocolMessageBytesStream.write(protocolMessageBytes);
        } catch (IOException ex) {
            // TODO Logger
        }
    }

    public void flushRecordBytes() {
        recordBytesStream = new ByteArrayOutputStream();
    }

    public void flushProtocolMessageBytes() {
        protocolMessageBytesStream = new ByteArrayOutputStream();
    }
}
