/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Record extends AbstractRecord {

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
     * Bytes which are not meta data which are going to be maced
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray nonMetaDataMaced;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray authenticatedMetaData;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    // TODO check types
    private ModifiableByteArray initialisationVector;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger epoch;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableBigInteger sequenceNumber;

    public Record(Config config) {
        super(config);
    }

    public Record() {
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

    public ModifiableByteArray getNonMetaDataMaced() {
        return nonMetaDataMaced;
    }

    public void setNonMetaDataMaced(ModifiableByteArray nonMetaDataMaced) {
        this.nonMetaDataMaced = nonMetaDataMaced;
    }

    public void setNonMetaDataMaced(byte[] nonMetaDataMaced) {
        this.nonMetaDataMaced = ModifiableVariableFactory.safelySetValue(this.nonMetaDataMaced, nonMetaDataMaced);
    }

    public ModifiableByteArray getAuthenticatedMetaData() {
        return authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(ModifiableByteArray authenticatedMetaData) {
        this.authenticatedMetaData = authenticatedMetaData;
    }

    public void setAuthenticatedMetaData(byte[] authenticatedMetaData) {
        this.authenticatedMetaData = ModifiableVariableFactory.safelySetValue(this.authenticatedMetaData,
                authenticatedMetaData);
    }

    public ModifiableByteArray getInitialisationVector() {
        return initialisationVector;
    }

    public void setInitialisationVector(ModifiableByteArray initialisationVector) {
        this.initialisationVector = initialisationVector;
    }

    public void setInitialisationVector(byte[] initialisationVector) {
        this.initialisationVector = ModifiableVariableFactory.safelySetValue(this.initialisationVector,
                initialisationVector);
    }

    @Override
    public RecordPreparator getRecordPreparator(Chooser chooser, Encryptor encryptor, ProtocolMessageType type) {
        return new RecordPreparator(chooser, this, encryptor, type);
    }

    @Override
    public RecordParser getRecordParser(int startposition, byte[] array, ProtocolVersion version) {
        return new RecordParser(0, array, version);
    }

    @Override
    public RecordSerializer getRecordSerializer() {
        return new RecordSerializer(this);
    }

    @Override
    public void adjustContext(TlsContext context) {
        ProtocolVersion version = ProtocolVersion.getProtocolVersion(getProtocolVersion().getValue());
        context.setLastRecordVersion(version);
    }
}
