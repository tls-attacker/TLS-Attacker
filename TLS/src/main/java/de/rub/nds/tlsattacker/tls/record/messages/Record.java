/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.record.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Record extends ModifiableVariableHolder {

    private static final Logger LOGGER = LogManager.getLogger(Record.class);

    /**
     * maximum length configuration for this record
     */
    private Integer maxRecordLengthConfig;

    /**
     * total length of the protocol message (handshake, alert..) included in the
     * record layer
     */
    ModifiableVariable<Integer> length;

    /**
     * Content type
     */
    ModifiableVariable<Byte> contentType;

    /**
     * Record Layer Protocol Version
     */
    ModifiableVariable<byte[]> protocolVersion;

    /**
     * protocol message bytes transported in the record
     */
    ModifiableVariable<byte[]> protocolMessageBytes;

    /**
     * MAC (message authentication code) for the record (if needed)
     */
    ModifiableVariable<byte[]> mac;

    /**
     * Padding
     */
    ModifiableVariable<byte[]> padding;

    /**
     * Padding length
     */
    ModifiableVariable<Integer> paddingLength;

    /**
     * encrypted protocol message bytes (if encryption activated)
     */
    ModifiableVariable<byte[]> encryptedProtocolMessageBytes;

    /**
     * It is possible to define a sleep [in milliseconds] after the protocol
     * message was sent. TODO: handle this or move it to the record?
     */
    private int sleepAfterMessageSent;

    public ModifiableVariable<Integer> getLength() {
	return length;
    }

    public ModifiableVariable<Byte> getContentType() {
	return contentType;
    }

    public ModifiableVariable<byte[]> getProtocolVersion() {
	return protocolVersion;
    }

    public ModifiableVariable<byte[]> getMac() {
	return mac;
    }

    public ModifiableVariable<byte[]> getPadding() {
	return padding;
    }

    public ModifiableVariable<byte[]> getProtocolMessageBytes() {
	return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(ModifiableVariable<byte[]> protocolMessageBytes) {
	this.protocolMessageBytes = protocolMessageBytes;
    }

    public void setLength(ModifiableVariable<Integer> length) {
	this.length = length;
    }

    public void setContentType(ModifiableVariable<Byte> contentType) {
	this.contentType = contentType;
    }

    public void setProtocolVersion(ModifiableVariable<byte[]> protocolVersion) {
	this.protocolVersion = protocolVersion;
    }

    public void setLength(int length) {
	if (this.length == null) {
	    this.length = new ModifiableVariable<>();
	}
	this.length.setOriginalValue(length);
    }

    public void setContentType(byte contentType) {
	if (this.contentType == null) {
	    this.contentType = new ModifiableVariable<>();
	}
	this.contentType.setOriginalValue(contentType);
    }

    public void setProtocolVersion(byte[] array) {
	if (this.protocolVersion == null) {
	    this.protocolVersion = new ModifiableVariable<>();
	}
	this.protocolVersion.setOriginalValue(array);
    }

    public void setMac(byte[] mac) {
	if (this.mac == null) {
	    this.mac = new ModifiableVariable<>();
	}
	this.mac.setOriginalValue(mac);
    }

    public void setPadding(byte[] padding) {
	if (this.padding == null) {
	    this.padding = new ModifiableVariable<>();
	}
	this.padding.setOriginalValue(padding);
    }

    public void setPadding(ModifiableVariable<byte[]> padding) {
	this.padding = padding;
    }

    public void setMac(ModifiableVariable<byte[]> mac) {
	this.mac = mac;
    }

    public void setProtocolMessageBytes(byte[] bytes) {
	if (this.protocolMessageBytes == null) {
	    this.protocolMessageBytes = new ModifiableVariable<>();
	}
	this.protocolMessageBytes.setOriginalValue(bytes);
    }

    public ModifiableVariable<Integer> getPaddingLength() {
	return paddingLength;
    }

    public void setPaddingLength(ModifiableVariable<Integer> paddingLength) {
	this.paddingLength = paddingLength;
    }

    public void setPaddingLength(int paddingLength) {
	if (this.paddingLength == null) {
	    this.paddingLength = new ModifiableVariable<>();
	}
	this.paddingLength.setOriginalValue(paddingLength);
    }

    public ModifiableVariable<byte[]> getEncryptedProtocolMessageBytes() {
	return encryptedProtocolMessageBytes;
    }

    public void setEncryptedProtocolMessageBytes(ModifiableVariable<byte[]> encryptedProtocolMessageBytes) {
	this.encryptedProtocolMessageBytes = encryptedProtocolMessageBytes;
    }

    public void setEncryptedProtocolMessageBytes(byte[] value) {
	if (this.encryptedProtocolMessageBytes == null) {
	    this.encryptedProtocolMessageBytes = new ModifiableVariable<>();
	}
	this.encryptedProtocolMessageBytes.setOriginalValue(value);
    }

    // public byte[] getBytes() {
    // byte[] ct = new byte[contentType.getValue()];
    // byte[] ret = ArrayConverter.concatenate(ct,
    // this.protocolVersion.getValue(),
    // ArrayConverter.intToBytes(this.length.getValue(), 2));
    //
    // for (HandshakeMessage pm : protocolMessages) {
    // ret = ArrayConverter.concatenate(ret);
    // }
    //
    // return ret;
    // }
    //
    // final void initializeModifiableVariableList() {
    // Class c = this.getClass();
    // try {
    // while (c != Object.class) {
    // for (Field f : c.getDeclaredFields()) {
    // if (f.getType().equals(ModifiableVariable.class)) {
    // variables.put(f.getName(), (ModifiableVariable) f.get(this));
    // }
    // }
    // c = c.getSuperclass();
    // }
    // } catch (IllegalAccessException | IllegalArgumentException |
    // SecurityException e) {
    // LOGGER.info("Cannot create map of modifiable variables", e);
    // }
    // }
    //
    // public Map<String, ModifiableVariable> getVariables() {
    // return variables;
    // }
    public Integer getMaxRecordLengthConfig() {
	return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
	this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public void setSleepAfterMessageSent(int sleepAfterMessageSent) {
	this.sleepAfterMessageSent = sleepAfterMessageSent;
    }

    public int getSleepAfterMessageSent() {
	return sleepAfterMessageSent;
    }
}
