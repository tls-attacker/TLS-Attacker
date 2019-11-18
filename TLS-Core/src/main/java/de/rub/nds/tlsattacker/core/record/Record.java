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
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

public class Record extends AbstractRecord {

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
     * total length of the protocol message (handshake, alert..) included in the
     * record layer
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    /**
     * protocol message bytes after decryption
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_RECORD)
    private ModifiableByteArray fragment;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger epoch;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableBigInteger sequenceNumber;

    private RecordCryptoComputations computations;

    public Record(Config config) {
        super(config);
    }

    public Record() {
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
        this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public RecordPreparator getRecordPreparator(Chooser chooser, Encryptor encryptor, RecordCompressor compressor,
            ProtocolMessageType type) {
        return new RecordPreparator(chooser, this, encryptor, type, compressor);
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

    public ModifiableByteArray getFragment() {
        return fragment;
    }

    public void setFragment(ModifiableByteArray fragment) {
        this.fragment = fragment;
    }

    public RecordCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(RecordCryptoComputations computations) {
        this.computations = computations;
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            this.computations = new RecordCryptoComputations();
        }
    }

    @Override
    public String toString() {
        return "Record{" + "contentType=" + contentType + ", protocolVersion=" + protocolVersion + ", length=" + length
                + '}';
    }

}
