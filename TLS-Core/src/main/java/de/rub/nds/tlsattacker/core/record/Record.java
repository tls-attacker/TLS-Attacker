/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Dtls13UnifiedHeaderBits;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.handler.RecordHandler;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.tcp.TcpSegmentConfiguration;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Record extends ModifiableVariableHolder implements DataContainer {

    @XmlTransient protected boolean shouldPrepareDefault = true;

    /** maximum length configuration for this record */
    private Integer maxRecordLengthConfig;

    @ModifiableVariableProperty private ModifiableByteArray completeRecordBytes;

    /**
     * protocol message bytes transported in the record as seen on the transport layer if encryption
     * is active this is encrypted if not its plaintext
     */
    @ModifiableVariableProperty private ModifiableByteArray protocolMessageBytes;

    /** The decrypted , unpadded, unmaced record bytes */
    @ModifiableVariableProperty private ModifiableByteArray cleanProtocolMessageBytes;

    private ProtocolMessageType contentMessageType;

    /** Content type */
    @ModifiableVariableProperty private ModifiableByte contentType;

    /** Record Layer Protocol Version */
    @ModifiableVariableProperty private ModifiableByteArray protocolVersion;

    /** total length of the protocol message (handshake, alert..) included in the record layer */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.LENGTH)
    private ModifiableInteger length;

    /** The epoch number for DTLS */
    @ModifiableVariableProperty private ModifiableInteger epoch;

    /**
     * This is the implicit sequence number in TLS and also the explicit sequence number in DTLS
     * This could also have been a separate field within the computations struct but i chose to only
     * keep one of them as the whole situation is already complicated enough
     */
    @ModifiableVariableProperty private ModifiableBigInteger sequenceNumber;

    /** The encrypted sequence number for DTLS 1.3 */
    @ModifiableVariableProperty private ModifiableByteArray encryptedSequenceNumber;

    /** The connectin ID for DTLS */
    @ModifiableVariableProperty private ModifiableByteArray connectionId;

    /** DTLS 1.3 unified header */
    @ModifiableVariableProperty private ModifiableByte unifiedHeader;

    private RecordCryptoComputations computations;

    /** TCP segmentation configuration for this record */
    @XmlElement(name = "tcpSegmentation")
    private TcpSegmentConfiguration tcpSegmentConfiguration;

    public Record(Config config) {
        this.maxRecordLengthConfig = config.getDefaultMaxRecordData();
    }

    public Record() {}

    public Record(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    @Override
    public boolean shouldPrepare() {
        return shouldPrepareDefault;
    }

    public void setShouldPrepare(boolean shouldPrepare) {
        this.shouldPrepareDefault = shouldPrepare;
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

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public void setContentType(ModifiableByte contentType) {
        this.contentType = contentType;
    }

    public void setContentType(byte contentType) {
        this.contentType = ModifiableVariableFactory.safelySetValue(this.contentType, contentType);
    }

    public void setProtocolVersion(ModifiableByteArray protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setProtocolVersion(byte[] array) {
        this.protocolVersion =
                ModifiableVariableFactory.safelySetValue(this.protocolVersion, array);
    }

    public ModifiableInteger getEpoch() {
        return epoch;
    }

    public void setEpoch(ModifiableInteger epoch) {
        this.epoch = epoch;
    }

    public void setEpoch(Integer epoch) {
        this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    public ModifiableBigInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public ModifiableByteArray getEncryptedSequenceNumber() {
        return encryptedSequenceNumber;
    }

    public void setEncryptedSequenceNumber(ModifiableByteArray encryptedSequenceNumber) {
        this.encryptedSequenceNumber = encryptedSequenceNumber;
    }

    public void setEncryptedSequenceNumber(byte[] encryptedSequenceNumber) {
        this.encryptedSequenceNumber =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedSequenceNumber, encryptedSequenceNumber);
    }

    public ModifiableByteArray getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(byte[] connectionId) {
        this.connectionId =
                ModifiableVariableFactory.safelySetValue(this.connectionId, connectionId);
    }

    public void setConnectionId(ModifiableByteArray connectionId) {
        this.connectionId = connectionId;
    }

    public RecordPreparator getRecordPreparator(
            TlsContext tlsContext,
            Encryptor encryptor,
            RecordCompressor compressor,
            ProtocolMessageType type) {
        return new RecordPreparator(tlsContext, this, encryptor, type, compressor);
    }

    public RecordParser getRecordParser(
            InputStream stream, ProtocolVersion version, TlsContext tlsContext) {
        return new RecordParser(stream, version, tlsContext);
    }

    public RecordSerializer getRecordSerializer() {
        return new RecordSerializer(this);
    }

    public ProtocolMessageType getContentMessageType() {
        return contentMessageType;
    }

    public void setContentMessageType(ProtocolMessageType contentMessageType) {
        this.contentMessageType = contentMessageType;
    }

    public ModifiableByteArray getCleanProtocolMessageBytes() {
        return cleanProtocolMessageBytes;
    }

    public void setCleanProtocolMessageBytes(byte[] cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.cleanProtocolMessageBytes, cleanProtocolMessageBytes);
    }

    public void setCleanProtocolMessageBytes(ModifiableByteArray cleanProtocolMessageBytes) {
        this.cleanProtocolMessageBytes = cleanProtocolMessageBytes;
    }

    public ModifiableByteArray getProtocolMessageBytes() {
        return protocolMessageBytes;
    }

    public void setProtocolMessageBytes(ModifiableByteArray protocolMessageBytes) {
        this.protocolMessageBytes = protocolMessageBytes;
    }

    public void setProtocolMessageBytes(byte[] bytes) {
        this.protocolMessageBytes =
                ModifiableVariableFactory.safelySetValue(this.protocolMessageBytes, bytes);
    }

    public Integer getMaxRecordLengthConfig() {
        return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public ModifiableByte getUnifiedHeader() {
        return unifiedHeader;
    }

    public void setUnifiedHeader(byte unifiedHeader) {
        this.unifiedHeader =
                ModifiableVariableFactory.safelySetValue(this.unifiedHeader, unifiedHeader);
    }

    public void setUnifiedHeader(ModifiableByte unifiedHeader) {
        this.unifiedHeader = unifiedHeader;
    }

    public boolean isUnifiedHeaderCidPresent() {
        return (unifiedHeader.getValue() & Dtls13UnifiedHeaderBits.CID_PRESENT) != 0;
    }

    public boolean isUnifiedHeaderSqnLong() {
        return (unifiedHeader.getValue() & Dtls13UnifiedHeaderBits.SQN_LONG) != 0;
    }

    public boolean isUnifiedHeaderLengthPresent() {
        return (unifiedHeader.getValue() & Dtls13UnifiedHeaderBits.LENGTH_PRESENT) != 0;
    }

    public ModifiableByteArray getCompleteRecordBytes() {
        return completeRecordBytes;
    }

    public void setCompleteRecordBytes(ModifiableByteArray completeRecordBytes) {
        this.completeRecordBytes = completeRecordBytes;
    }

    public void setCompleteRecordBytes(byte[] completeRecordBytes) {
        this.completeRecordBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.completeRecordBytes, completeRecordBytes);
    }

    public RecordCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(RecordCryptoComputations computations) {
        this.computations = computations;
    }

    public void prepareComputations() {
        if (computations == null) {
            this.computations = new RecordCryptoComputations();
        }
    }

    public TcpSegmentConfiguration getTcpSegmentConfiguration() {
        return tcpSegmentConfiguration;
    }

    public void setTcpSegmentConfiguration(TcpSegmentConfiguration tcpSegmentConfiguration) {
        this.tcpSegmentConfiguration = tcpSegmentConfiguration;
    }

    @Override
    public String toString() {

        String contentTypeString;
        if (contentType == null || contentType.getOriginalValue() == null) {
            contentTypeString = "null";
        } else {
            ProtocolMessageType type = ProtocolMessageType.getContentType(contentType.getValue());
            if (type == null) {
                contentTypeString = "UNKNOWN";
            } else {
                contentTypeString = type.name();
            }
        }
        String protocolVersionString;
        if (protocolVersion == null || protocolVersion.getOriginalValue() == null) {
            protocolVersionString = "null";
        } else {
            ProtocolVersion version =
                    ProtocolVersion.getProtocolVersion(protocolVersion.getValue());
            if (version == null) {
                protocolVersionString = "UNKNOWN";
            } else {
                protocolVersionString = version.name();
            }
        }
        String lengthString;
        if (length == null || length.getOriginalValue() == null) {
            lengthString = "null";
        } else {
            lengthString = length.getValue().toString();
        }
        return "Record["
                + contentTypeString
                + ", "
                + protocolVersionString
                + ", "
                + lengthString
                + ']';
    }

    @Override
    public String toCompactString() {
        String stringContentType = "unspecified";
        String stringProtocolVersion = "unspecified";
        String stringLength = "unspecified";
        if (contentType != null && contentType.getValue() != null) {
            stringContentType = contentType.getValue().toString();
        }
        if (protocolVersion != null && protocolVersion.getValue() != null) {
            stringContentType = ArrayConverter.bytesToHexString(protocolVersion.getValue());
        }
        if (length != null && length.getValue() != null) {
            stringLength = length.getValue().toString();
        } else if (maxRecordLengthConfig != null) {
            stringLength = maxRecordLengthConfig.toString();
        }
        return "Record{"
                + "contentType="
                + stringContentType
                + ", protocolVersion="
                + stringProtocolVersion
                + ", length="
                + stringLength
                + '}';
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 29 * hash + Objects.hashCode(this.contentType);
        hash = 29 * hash + Objects.hashCode(this.protocolVersion);
        hash = 29 * hash + Objects.hashCode(this.length);
        hash = 29 * hash + Objects.hashCode(this.epoch);
        hash = 29 * hash + Objects.hashCode(this.sequenceNumber);
        hash = 29 * hash + Objects.hashCode(this.encryptedSequenceNumber);
        hash = 29 * hash + Objects.hashCode(this.connectionId);
        hash = 29 * hash + Objects.hashCode(this.computations);
        hash = 29 * hash + Objects.hashCode(this.unifiedHeader);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Record other = (Record) obj;
        if (!Objects.equals(this.contentType, other.contentType)) {
            return false;
        }
        if (!Objects.equals(this.protocolVersion, other.protocolVersion)) {
            return false;
        }
        if (!Objects.equals(this.length, other.length)) {
            return false;
        }
        if (!Objects.equals(this.epoch, other.epoch)) {
            return false;
        }
        if (!Objects.equals(this.sequenceNumber, other.sequenceNumber)) {
            return false;
        }
        if (!Objects.equals(this.encryptedSequenceNumber, other.encryptedSequenceNumber)) {
            return false;
        }
        if (!Objects.equals(this.connectionId, other.connectionId)) {
            return false;
        }
        if (!Objects.equals(this.computations, other.computations)) {
            return false;
        }
        if (!Objects.equals(this.unifiedHeader, other.unifiedHeader)) {
            return false;
        }
        return true;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }

    @Override
    public void reset() {
        super.reset();
        setContentMessageType(null);
    }

    // TODO Fix this mess for records
    @Override
    public RecordParser getParser(Context context, InputStream stream) {
        return new RecordParser(
                stream, context.getTlsContext().getLastRecordVersion(), context.getTlsContext());
    }

    @Override
    public RecordPreparator getPreparator(Context context) {
        return new RecordPreparator(context.getTlsContext(), this, null, contentMessageType, null);
    }

    @Override
    public RecordSerializer getSerializer(Context context) {
        return new RecordSerializer(this);
    }

    @Override
    public Handler<Record> getHandler(Context context) {
        return new RecordHandler(context.getTlsContext());
    }
}
