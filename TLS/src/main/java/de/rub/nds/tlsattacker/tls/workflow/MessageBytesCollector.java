/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
