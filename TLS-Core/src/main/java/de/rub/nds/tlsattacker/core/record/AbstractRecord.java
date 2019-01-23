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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor;
import de.rub.nds.tlsattacker.core.record.crypto.Encryptor;
import de.rub.nds.tlsattacker.core.record.parser.AbstractRecordParser;
import de.rub.nds.tlsattacker.core.record.preparator.AbstractRecordPreparator;
import de.rub.nds.tlsattacker.core.record.serializer.AbstractRecordSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class AbstractRecord extends ModifiableVariableHolder {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray completeRecordBytes;

    /**
     * protocol message bytes transported in the record as seen on the transport
     * layer if encrypption is active this is encrypted if not its plaintext
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray protocolMessageBytes;

    /**
     * The decrypted , unpadded, unmaced record bytes
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray cleanProtocolMessageBytes;

    private ProtocolMessageType contentMessageType;
    /**
     * maximum length configuration for this record
     */
    private Integer maxRecordLengthConfig;

    public AbstractRecord() {
    }

    public AbstractRecord(Config config) {
        this.maxRecordLengthConfig = config.getDefaultMaxRecordData();
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
        this.cleanProtocolMessageBytes = ModifiableVariableFactory.safelySetValue(this.cleanProtocolMessageBytes,
                cleanProtocolMessageBytes);
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
        this.protocolMessageBytes = ModifiableVariableFactory.safelySetValue(this.protocolMessageBytes, bytes);
    }

    public Integer getMaxRecordLengthConfig() {
        return maxRecordLengthConfig;
    }

    public void setMaxRecordLengthConfig(Integer maxRecordLengthConfig) {
        this.maxRecordLengthConfig = maxRecordLengthConfig;
    }

    public ModifiableByteArray getCompleteRecordBytes() {
        return completeRecordBytes;
    }

    public void setCompleteRecordBytes(ModifiableByteArray completeRecordBytes) {
        this.completeRecordBytes = completeRecordBytes;
    }

    public void setCompleteRecordBytes(byte[] completeRecordBytes) {
        this.completeRecordBytes = ModifiableVariableFactory.safelySetValue(this.completeRecordBytes,
                completeRecordBytes);
    }

    public abstract AbstractRecordPreparator getRecordPreparator(Chooser chooser, Encryptor encryptor,
            RecordCompressor compressor, ProtocolMessageType type);

    public abstract AbstractRecordParser getRecordParser(int startposition, byte[] array, ProtocolVersion version);

    public abstract AbstractRecordSerializer getRecordSerializer();

    public abstract void adjustContext(TlsContext context);

    public abstract void prepareComputations();
}
