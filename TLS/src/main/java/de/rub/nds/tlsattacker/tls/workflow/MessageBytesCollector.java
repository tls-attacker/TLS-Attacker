/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class MessageBytesCollector {

    private byte[] recordBytes;

    private byte[] protocolMessageBytes;

    public MessageBytesCollector() {
	this.recordBytes = new byte[0];
	this.protocolMessageBytes = new byte[0];
    }

    public byte[] getRecordBytes() {
	return recordBytes;
    }

    public void setRecordBytes(byte[] recordBytes) {
	this.recordBytes = recordBytes;
    }

    public byte[] getProtocolMessageBytes() {
	return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(byte[] protocolMessageBytes) {
	this.protocolMessageBytes = protocolMessageBytes;
    }

    public void appendRecordBytes(byte[] recordBytes) {
	this.recordBytes = ArrayConverter.concatenate(this.recordBytes, recordBytes);
    }

    public void appendProtocolMessageBytes(byte[] protocolMessageBytes) {
	this.protocolMessageBytes = ArrayConverter.concatenate(this.protocolMessageBytes, protocolMessageBytes);
    }

    public void flushRecordBytes() {
	this.recordBytes = new byte[0];
    }

    public void flushProtocolMessageBytes() {
	this.protocolMessageBytes = new byte[0];
    }
}
