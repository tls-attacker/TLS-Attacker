/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.record;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Record extends ModifiableVariableHolder {

    /**
     * maximum length configuration for this record
     */
    private Integer maxRecordLengthConfig;

    /**
     * This record should only contain a single Message
     */
    private boolean bounceToMessage;

    /**
     * total length of the protocol message (handshake, alert..) included in the
     * record layer
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    /**
     * Content type
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByte contentType;

    /**
     * Record Layer Protocol Version
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray protocolVersion;

    /**
     * MAC (message authentication code) for the record (if needed)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray mac;

    /**
     * Padding
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    private ModifiableByteArray padding;

    /**
     * Padding length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger paddingLength;

    /**
     * protocol message bytes transported in the record as seen on the transport
     * layer if encrypption is active this is encrypted if not its plaintext
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray protocolMessageBytes;

    /**
     * protocol message bytes after decryption
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    private ModifiableByteArray plainRecordBytes;

    /**
     * protocol message bytes after decryption without padding (if there was
     * one)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray unpaddedRecordBytes;

    /**
     * The decrypted , unpadded, unmaced record bytes
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray cleanProtocolMessageBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger epoch;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableBigInteger sequenceNumber;

    public Record(TlsConfig config) {
        this.maxRecordLengthConfig = config.getDefaultMaxRecordData();
    }

    public Record() {
    }

    public ModifiableByteArray getCleanProtocolMessageBytes() {
        return cleanProtocolMessageBytes;
    }

    public void setCleanProtocolMessageBytes(byte[] cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes = ModifiableVariableFactory.safelySetValue(this.cleanProtocolMessageBytes,
                cleanProtocolMessageBytes);
    }

    public void setCleanProtocolMessageBytes(ModifiableByteArray cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes = cleanProtocolMessageBytes;
    }

    public ModifiableInteger getEpoch() {
        return epoch;
    }

    public ModifiableBigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setEpoch(int epoch) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    public void setEpoch(ModifiableInteger epoch) {
        this.epoch = epoch;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
        this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public ModifiableByte getContentType() {
        return contentType;
    }

    public ModifiableByteArray getProtocolVersion() {
        return protocolVersion;
    }

    public ModifiableByteArray getMac() {
        return mac;
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public ModifiableByteArray getProtocolMessageBytes() {
        return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(ModifiableByteArray protocolMessageBytes) {
        this.protocolMessageBytes = protocolMessageBytes;
    }

    public void setProtocolMessageBytes(byte[] bytes) {
        this.protocolMessageBytes = ModifiableVariableFactory.safelySetValue(this.protocolMessageBytes, bytes);
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setContentType(ModifiableByte contentType) {
        this.contentType = contentType;
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public void setContentType(byte contentType) {
        this.contentType = ModifiableVariableFactory.safelySetValue(this.contentType, contentType);
    }

    public void setProtocolVersion(byte[] array) {
        this.protocolVersion = ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public ModifiableInteger getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(int paddingLength) {
        this.paddingLength = ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public ModifiableByteArray getPlainRecordBytes() {
        return plainRecordBytes;
    }

    public void setPlainRecordBytes(ModifiableByteArray plainRecordBytes) {
        this.plainRecordBytes = plainRecordBytes;
    }

    public void setPlainRecordBytes(byte[] plainRecordBytes) {
        this.plainRecordBytes = ModifiableVariableFactory.safelySetValue(this.plainRecordBytes, plainRecordBytes);
    }

    public Integer getMaxRecordLengthConfig() {
        return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public ModifiableByteArray getUnpaddedRecordBytes() {
        return unpaddedRecordBytes;
    }

    public void setUnpaddedRecordBytes(ModifiableByteArray unpaddedRecordBytes) {
        this.unpaddedRecordBytes = unpaddedRecordBytes;
    }

    public void setUnpaddedRecordBytes(byte[] unpaddedRecordBytes) {
        this.unpaddedRecordBytes = ModifiableVariableFactory.safelySetValue(this.unpaddedRecordBytes,
                unpaddedRecordBytes);
    }
}
