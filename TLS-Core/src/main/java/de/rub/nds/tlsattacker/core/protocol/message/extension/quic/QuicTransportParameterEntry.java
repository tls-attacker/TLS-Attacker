/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicTransportParameterEntry extends ModifiableVariableHolder implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private QuicTransportParameterEntryTypes entryType;
    private ModifiableByteArray entryValue;

    private ModifiableByte entryLength;

    public QuicTransportParameterEntry() {}

    public QuicTransportParameterEntry(
            QuicTransportParameterEntryTypes entryType, String entryValue) {
        this.entryType = entryType;
        this.setEntryValue(ArrayConverter.hexStringToByteArray(entryValue));
        this.setEntryLength((byte) this.entryValue.getValue().length);
    }

    public QuicTransportParameterEntry(
            QuicTransportParameterEntryTypes entryType, byte[] entryValue) {
        this.entryType = entryType;
        this.setEntryValue(entryValue);
        this.setEntryLength((byte) this.entryValue.getValue().length);
    }

    public QuicTransportParameterEntry(
            QuicTransportParameterEntryTypes entryType, long entryValue) {
        this.entryType = entryType;
        this.setEntryValue(VariableLengthIntegerEncoding.encodeVariableLengthInteger(entryValue));
        this.setEntryLength((byte) this.entryValue.getValue().length);
    }

    public QuicTransportParameterEntryTypes getEntryType() {
        return entryType;
    }

    public ModifiableByteArray getEntryValue() {
        return entryValue;
    }

    public void setEntryValue(ModifiableByteArray entryValue) {
        this.entryValue = entryValue;
    }

    public void setEntryValue(byte[] entryValue) {
        this.entryValue = ModifiableVariableFactory.safelySetValue(this.entryValue, entryValue);
    }

    public ModifiableByte getEntryLength() {
        return entryLength;
    }

    public void setEntryLength(ModifiableByte entryLength) {
        this.entryLength = entryLength;
    }

    public void setEntryLength(byte entryLength) {
        this.entryLength = ModifiableVariableFactory.safelySetValue(this.entryLength, entryLength);
    }

    public void setEntryType(QuicTransportParameterEntryTypes entryType) {
        this.entryType = entryType;
    }

    public String entryValueToString() {
        switch (entryType) {
            case ORIGINAL_DESTINATION_CONNECTION_ID:
            case INITIAL_SOURCE_CONNECTION_ID:
            case RETRY_SOURCE_CONNECTION_ID:
                return ArrayConverter.bytesToHexString(this.entryValue);
            case MAX_IDLE_TIMEOUT:
            case MAX_UDP_PAYLOAD_SIZE:
            case INITIAL_MAX_DATA:
            case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            case INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            case INITIAL_MAX_STREAM_DATA_UNI:
            case INITIAL_MAX_STREAMS_BIDI:
            case INITIAL_MAX_STREAMS_UNI:
            case ACK_DELAY_EXPONENT:
            case MAX_ACK_DELAY:
            case ACTIVE_CONNECTION_ID_LIMIT:
                return Long.toString(
                        VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                this.entryValue.getValue()));
            case DISABLE_ACTIVE_MIGRATION:
                return "TRUE";
            case PREFERRED_ADDRESS:
                return (new QuicTransportParametersExtensionMessage.PreferredAddress(
                                this.entryValue.getValue()))
                        .toString();
            default:
                return ArrayConverter.bytesToHexString(this.entryValue);
        }
    }

    @Override
    public String toString() {
        return this.entryType.name() + ": " + entryValueToString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        QuicTransportParameterEntry that = (QuicTransportParameterEntry) o;

        if (entryType != that.entryType) {
            return false;
        }
        if (!Arrays.equals(entryValue.getValue(), that.entryValue.getValue())) {
            return false;
        }
        return Objects.equals(entryLength, that.entryLength);
    }

    @Override
    public int hashCode() {
        int result = entryType != null ? entryType.hashCode() : 0;
        result = 31 * result + (entryValue != null ? entryValue.hashCode() : 0);
        result = 31 * result + (entryLength != null ? entryLength.hashCode() : 0);
        return result;
    }
}
