/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic;

import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.ACK_DELAY_EXPONENT;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.ACTIVE_CONNECTION_ID_LIMIT;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.DISABLE_ACTIVE_MIGRATION;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_DATA;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_STREAMS_BIDI;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_STREAMS_UNI;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_MAX_STREAM_DATA_UNI;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.INITIAL_SOURCE_CONNECTION_ID;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.MAX_ACK_DELAY;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.MAX_IDLE_TIMEOUT;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.MAX_UDP_PAYLOAD_SIZE;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.ORIGINAL_DESTINATION_CONNECTION_ID;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.PREFERRED_ADDRESS;
import static de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes.RETRY_SOURCE_CONNECTION_ID;

import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** POJO variant of QuicTransportParameters */
public class QuicTransportParameters {

    private byte[] originalDestinationConnectionId;

    private byte[] initialSourceConnectionId;

    private byte[] retrySourceConnectionId;

    private Long maxIdleTimeout;
    private Long maxUdpPayloadSize;
    private Long initialMaxData;
    private Long initialMaxStreamDataBidiLocal;
    private Long initialMaxStreamDataBidiRemote;
    private Long initialMaxStreamDataUni;
    private Long initialMaxStreamsBidi;
    private Long initialMaxStreamsUni;
    private Long ackDelayExponent;
    private Long maxAckDelay;
    private Long activeConnectionIdLimit;

    private boolean disableActiveMigration;

    private List<QuicTransportParameterEntry> extraEntries;

    private QuicTransportParametersExtensionMessage.PreferredAddress preferredAddress;

    public QuicTransportParameters() {}

    public QuicTransportParameters(
            List<QuicTransportParameterEntry> quicTransportParameterEntryList) {
        this.extraEntries = new ArrayList<>();
        for (QuicTransportParameterEntry parameterEntry : quicTransportParameterEntryList) {
            switch (parameterEntry.getEntryType()) {
                case ORIGINAL_DESTINATION_CONNECTION_ID:
                    this.originalDestinationConnectionId =
                            parameterEntry.getEntryValue().getValue();
                    break;
                case INITIAL_SOURCE_CONNECTION_ID:
                    this.initialSourceConnectionId = parameterEntry.getEntryValue().getValue();
                    break;
                case RETRY_SOURCE_CONNECTION_ID:
                    this.retrySourceConnectionId = parameterEntry.getEntryValue().getValue();
                    break;
                case MAX_IDLE_TIMEOUT:
                    this.maxIdleTimeout =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case MAX_UDP_PAYLOAD_SIZE:
                    this.maxUdpPayloadSize =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_DATA:
                    this.initialMaxData =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
                    this.initialMaxStreamDataBidiLocal =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
                    this.initialMaxStreamDataBidiRemote =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_STREAM_DATA_UNI:
                    this.initialMaxStreamDataUni =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_STREAMS_BIDI:
                    this.initialMaxStreamsBidi =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case INITIAL_MAX_STREAMS_UNI:
                    this.initialMaxStreamsUni =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case ACK_DELAY_EXPONENT:
                    this.ackDelayExponent =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case MAX_ACK_DELAY:
                    this.maxAckDelay =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case ACTIVE_CONNECTION_ID_LIMIT:
                    this.activeConnectionIdLimit =
                            VariableLengthIntegerEncoding.decodeVariableLengthInteger(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                case DISABLE_ACTIVE_MIGRATION:
                    this.disableActiveMigration = true;
                    break;
                case PREFERRED_ADDRESS:
                    this.preferredAddress =
                            new QuicTransportParametersExtensionMessage.PreferredAddress(
                                    parameterEntry.getEntryValue().getValue());
                    break;
                default:
                    this.extraEntries.add(parameterEntry);
                    break;
            }
        }
    }

    public static QuicTransportParameters getDefaultParameters() {
        QuicTransportParameters quicTransportParameters = new QuicTransportParameters();
        quicTransportParameters.setMaxIdleTimeout(60000L);
        quicTransportParameters.setMaxUdpPayloadSize(65527L);
        quicTransportParameters.setInitialMaxData(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataBidiLocal(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataBidiRemote(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataUni(2149983648L);
        quicTransportParameters.setInitialMaxStreamsBidi(2147745792L);
        quicTransportParameters.setInitialMaxStreamsUni(2147745792L);
        quicTransportParameters.setAckDelayExponent(0L);
        quicTransportParameters.setMaxAckDelay(2000L);
        return quicTransportParameters;
    }

    public List<QuicTransportParameterEntry> toListOfEntries() {
        List<QuicTransportParameterEntry> entryList = new ArrayList<>();
        if (this.originalDestinationConnectionId != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            ORIGINAL_DESTINATION_CONNECTION_ID,
                            this.originalDestinationConnectionId));
        }
        if (this.initialSourceConnectionId != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_SOURCE_CONNECTION_ID, this.initialSourceConnectionId));
        }
        if (this.retrySourceConnectionId != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            RETRY_SOURCE_CONNECTION_ID, this.retrySourceConnectionId));
        }
        if (this.maxIdleTimeout != null) {
            entryList.add(new QuicTransportParameterEntry(MAX_IDLE_TIMEOUT, this.maxIdleTimeout));
        }
        if (this.maxUdpPayloadSize != null) {
            entryList.add(
                    new QuicTransportParameterEntry(MAX_UDP_PAYLOAD_SIZE, this.maxUdpPayloadSize));
        }
        if (this.initialMaxData != null) {
            entryList.add(new QuicTransportParameterEntry(INITIAL_MAX_DATA, this.initialMaxData));
        }
        if (this.initialMaxStreamDataBidiLocal != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                            this.initialMaxStreamDataBidiLocal));
        }
        if (this.initialMaxStreamDataBidiRemote != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                            this.initialMaxStreamDataBidiRemote));
        }
        if (this.initialMaxStreamDataUni != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_MAX_STREAM_DATA_UNI, this.initialMaxStreamDataUni));
        }
        if (this.initialMaxStreamsBidi != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_MAX_STREAMS_BIDI, this.initialMaxStreamsBidi));
        }
        if (this.initialMaxStreamsUni != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            INITIAL_MAX_STREAMS_UNI, this.initialMaxStreamsUni));
        }
        if (this.ackDelayExponent != null) {
            entryList.add(
                    new QuicTransportParameterEntry(ACK_DELAY_EXPONENT, this.ackDelayExponent));
        }
        if (this.maxAckDelay != null) {
            entryList.add(new QuicTransportParameterEntry(MAX_ACK_DELAY, this.maxAckDelay));
        }
        if (this.disableActiveMigration) {
            entryList.add(new QuicTransportParameterEntry(DISABLE_ACTIVE_MIGRATION, new byte[] {}));
        }
        if (this.preferredAddress != null) {
            try {
                entryList.add(
                        new QuicTransportParameterEntry(
                                PREFERRED_ADDRESS, this.preferredAddress.serialize()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        if (this.activeConnectionIdLimit != null) {
            entryList.add(
                    new QuicTransportParameterEntry(
                            ACTIVE_CONNECTION_ID_LIMIT, this.activeConnectionIdLimit));
        }
        if (this.extraEntries != null) {
            entryList.addAll(this.extraEntries);
        }
        return entryList;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        QuicTransportParameters that = (QuicTransportParameters) o;

        if (!Objects.equals(maxIdleTimeout, that.maxIdleTimeout)) {
            return false;
        }
        if (!Objects.equals(maxUdpPayloadSize, that.maxUdpPayloadSize)) {
            return false;
        }
        if (!Objects.equals(initialMaxData, that.initialMaxData)) {
            return false;
        }
        if (!Objects.equals(initialMaxStreamDataBidiLocal, that.initialMaxStreamDataBidiLocal)) {
            return false;
        }
        if (!Objects.equals(initialMaxStreamDataBidiRemote, that.initialMaxStreamDataBidiRemote)) {
            return false;
        }
        if (!Objects.equals(initialMaxStreamDataUni, that.initialMaxStreamDataUni)) {
            return false;
        }
        if (!Objects.equals(initialMaxStreamsBidi, that.initialMaxStreamsBidi)) {
            return false;
        }
        if (!Objects.equals(initialMaxStreamsUni, that.initialMaxStreamsUni)) {
            return false;
        }
        if (!Objects.equals(ackDelayExponent, that.ackDelayExponent)) {
            return false;
        }
        if (!Objects.equals(maxAckDelay, that.maxAckDelay)) {
            return false;
        }
        if (!Objects.equals(activeConnectionIdLimit, that.activeConnectionIdLimit)) {
            return false;
        }
        if (disableActiveMigration != that.disableActiveMigration) {
            return false;
        }
        if (!Arrays.equals(originalDestinationConnectionId, that.originalDestinationConnectionId)) {
            return false;
        }
        if (!Arrays.equals(initialSourceConnectionId, that.initialSourceConnectionId)) {
            return false;
        }
        if (!Arrays.equals(retrySourceConnectionId, that.retrySourceConnectionId)) {
            return false;
        }
        if (extraEntries != null && !extraEntries.containsAll(that.extraEntries)) {
            return false;
        }
        return Objects.equals(preferredAddress, that.preferredAddress);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(originalDestinationConnectionId);
        result = 31 * result + Arrays.hashCode(initialSourceConnectionId);
        result = 31 * result + Arrays.hashCode(retrySourceConnectionId);
        result = 31 * result + (int) (maxIdleTimeout ^ (maxIdleTimeout >>> 32));
        result = 31 * result + (int) (maxUdpPayloadSize ^ (maxUdpPayloadSize >>> 32));
        result = 31 * result + (int) (initialMaxData ^ (initialMaxData >>> 32));
        result =
                31 * result
                        + (int)
                                (initialMaxStreamDataBidiLocal
                                        ^ (initialMaxStreamDataBidiLocal >>> 32));
        result =
                31 * result
                        + (int)
                                (initialMaxStreamDataBidiRemote
                                        ^ (initialMaxStreamDataBidiRemote >>> 32));
        result = 31 * result + (int) (initialMaxStreamDataUni ^ (initialMaxStreamDataUni >>> 32));
        result = 31 * result + (int) (initialMaxStreamsBidi ^ (initialMaxStreamsBidi >>> 32));
        result = 31 * result + (int) (initialMaxStreamsUni ^ (initialMaxStreamsUni >>> 32));
        result = 31 * result + (int) (ackDelayExponent ^ (ackDelayExponent >>> 32));
        result = 31 * result + (int) (maxAckDelay ^ (maxAckDelay >>> 32));
        result = 31 * result + (int) (activeConnectionIdLimit ^ (activeConnectionIdLimit >>> 32));
        result = 31 * result + (disableActiveMigration ? 1 : 0);
        result = 31 * result + (extraEntries != null ? extraEntries.hashCode() : 0);
        result = 31 * result + (preferredAddress != null ? preferredAddress.hashCode() : 0);
        return result;
    }

    public byte[] getOriginalDestinationConnectionId() {
        return originalDestinationConnectionId;
    }

    public void setOriginalDestinationConnectionId(byte[] originalDestinationConnectionId) {
        this.originalDestinationConnectionId = originalDestinationConnectionId;
    }

    public byte[] getInitialSourceConnectionId() {
        return initialSourceConnectionId;
    }

    public void setInitialSourceConnectionId(byte[] initialSourceConnectionId) {
        this.initialSourceConnectionId = initialSourceConnectionId;
    }

    public byte[] getRetrySourceConnectionId() {
        return retrySourceConnectionId;
    }

    public void setRetrySourceConnectionId(byte[] retrySourceConnectionId) {
        this.retrySourceConnectionId = retrySourceConnectionId;
    }

    public Long getMaxIdleTimeout() {
        return maxIdleTimeout;
    }

    public void setMaxIdleTimeout(Long maxIdleTimeout) {
        this.maxIdleTimeout = maxIdleTimeout;
    }

    public Long getMaxUdpPayloadSize() {
        return maxUdpPayloadSize;
    }

    public void setMaxUdpPayloadSize(Long maxUdpPayloadSize) {
        this.maxUdpPayloadSize = maxUdpPayloadSize;
    }

    public Long getInitialMaxData() {
        return initialMaxData;
    }

    public void setInitialMaxData(Long initialMaxData) {
        this.initialMaxData = initialMaxData;
    }

    public Long getInitialMaxStreamDataBidiLocal() {
        return initialMaxStreamDataBidiLocal;
    }

    public void setInitialMaxStreamDataBidiLocal(Long initialMaxStreamDataBidiLocal) {
        this.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal;
    }

    public Long getInitialMaxStreamDataBidiRemote() {
        return initialMaxStreamDataBidiRemote;
    }

    public void setInitialMaxStreamDataBidiRemote(Long initialMaxStreamDataBidiRemote) {
        this.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote;
    }

    public Long getInitialMaxStreamDataUni() {
        return initialMaxStreamDataUni;
    }

    public void setInitialMaxStreamDataUni(Long initialMaxStreamDataUni) {
        this.initialMaxStreamDataUni = initialMaxStreamDataUni;
    }

    public Long getInitialMaxStreamsBidi() {
        return initialMaxStreamsBidi;
    }

    public void setInitialMaxStreamsBidi(Long initialMaxStreamsBidi) {
        this.initialMaxStreamsBidi = initialMaxStreamsBidi;
    }

    public Long getInitialMaxStreamsUni() {
        return initialMaxStreamsUni;
    }

    public void setInitialMaxStreamsUni(Long initialMaxStreamsUni) {
        this.initialMaxStreamsUni = initialMaxStreamsUni;
    }

    public Long getAckDelayExponent() {
        return ackDelayExponent;
    }

    public void setAckDelayExponent(Long ackDelayExponent) {
        this.ackDelayExponent = ackDelayExponent;
    }

    public Long getMaxAckDelay() {
        return maxAckDelay;
    }

    public void setMaxAckDelay(Long maxAckDelay) {
        this.maxAckDelay = maxAckDelay;
    }

    public Long getActiveConnectionIdLimit() {
        return activeConnectionIdLimit;
    }

    public void setActiveConnectionIdLimit(Long activeConnectionIdLimit) {
        this.activeConnectionIdLimit = activeConnectionIdLimit;
    }

    public boolean isDisableActiveMigration() {
        return disableActiveMigration;
    }

    public void setDisableActiveMigration(boolean disableActiveMigration) {
        this.disableActiveMigration = disableActiveMigration;
    }

    public List<QuicTransportParameterEntry> getExtraEntries() {
        return extraEntries;
    }

    public void setExtraEntries(List<QuicTransportParameterEntry> extraEntries) {
        this.extraEntries = new ArrayList<>(extraEntries);
    }

    public QuicTransportParametersExtensionMessage.PreferredAddress getPreferredAddress() {
        return preferredAddress;
    }

    public void setPreferredAddress(
            QuicTransportParametersExtensionMessage.PreferredAddress preferredAddress) {
        this.preferredAddress = preferredAddress;
    }
}
