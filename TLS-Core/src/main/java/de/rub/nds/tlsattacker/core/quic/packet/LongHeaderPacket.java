/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Long headers are used for packets that are sent prior to the establishment of 1-RTT keys. */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlSeeAlso({
    LongHeaderPacket.class,
    InitialPacket.class,
    HandshakePacket.class,
    VersionNegotiationPacket.class,
    RetryPacket.class,
    ZeroRTTPacket.class
})
public abstract class LongHeaderPacket extends QuicPacket {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty protected ModifiableByteArray quicVersion;

    @ModifiableVariableProperty protected ModifiableByte sourceConnectionIdLength;

    @ModifiableVariableProperty protected ModifiableByteArray sourceConnectionId;

    public LongHeaderPacket(QuicPacketType packetType) {
        super(packetType);
    }

    @Override
    public void buildUnprotectedPacketHeader() {
        try {
            unprotectedHeaderHelper.write(unprotectedFlags.getValue());
            offsetToPacketNumber++;

            unprotectedHeaderHelper.write(quicVersion.getValue());
            offsetToPacketNumber += quicVersion.getValue().length;

            unprotectedHeaderHelper.write((byte) destinationConnectionId.getValue().length);
            offsetToPacketNumber++;

            unprotectedHeaderHelper.write(destinationConnectionId.getValue());
            offsetToPacketNumber += destinationConnectionIdLength.getValue();

            unprotectedHeaderHelper.write((byte) sourceConnectionId.getValue().length);
            offsetToPacketNumber++;

            unprotectedHeaderHelper.write(sourceConnectionId.getValue());
            offsetToPacketNumber += sourceConnectionIdLength.getValue();

            byte[] packetLengthBytes =
                    VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                            packetLength.getValue());
            unprotectedHeaderHelper.write(packetLengthBytes);
            offsetToPacketNumber += packetLengthBytes.length;

            unprotectedHeaderHelper.writeBytes(getUnprotectedPacketNumber().getValue());
            offsetToPacketNumber += getUnprotectedPacketNumber().getValue().length;

            completeUnprotectedHeader =
                    ModifiableVariableFactory.safelySetValue(
                            completeUnprotectedHeader, unprotectedHeaderHelper.toByteArray());
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    @Override
    public void convertCompleteProtectedHeader() {
        byte[] protectedHeaderBytes = protectedHeaderHelper.toByteArray();
        protectedHeaderBytes[0] = unprotectedFlags.getValue();
        offsetToPacketNumber =
                QuicPacketByteLength.QUIC_FIRST_HEADER_BYTE
                        + QuicPacketByteLength.QUIC_VERSION_LENGTH
                        + QuicPacketByteLength.DESTINATION_CONNECTION_ID_LENGTH
                        + destinationConnectionId.getValue().length
                        + QuicPacketByteLength.SOURCE_CONNECTION_ID_LENGTH
                        + sourceConnectionId.getValue().length
                        + packetLengthSize;
        this.completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(
                        this.completeUnprotectedHeader, protectedHeaderBytes);
    }

    public void setSourceConnectionId(ModifiableByteArray sourceConnectionId) {
        this.sourceConnectionId = sourceConnectionId;
    }

    public void setSourceConnectionId(byte[] sourceConnectionId) {
        this.sourceConnectionId =
                ModifiableVariableFactory.safelySetValue(
                        this.sourceConnectionId, sourceConnectionId);
    }

    public void setSourceConnectionIdLength(ModifiableByte sourceConnectionIdLength) {
        this.sourceConnectionIdLength = sourceConnectionIdLength;
    }

    public void setSourceConnectionIdLength(byte variableLengthInteger) {
        this.sourceConnectionIdLength =
                ModifiableVariableFactory.safelySetValue(
                        this.sourceConnectionIdLength, variableLengthInteger);
    }

    public void setQuicVersion(ModifiableByteArray quicVersion) {
        this.quicVersion = quicVersion;
    }

    public void setQuicVersion(byte[] quicVersion) {
        this.quicVersion = ModifiableVariableFactory.safelySetValue(this.quicVersion, quicVersion);
    }

    public void setQuicVersion(QuicVersion quicVersion) {
        this.setQuicVersion(quicVersion.getByteValue());
    }

    public ModifiableByteArray getSourceConnectionId() {
        return sourceConnectionId;
    }

    public ModifiableByte getSourceConnectionIdLength() {
        return sourceConnectionIdLength;
    }

    public ModifiableByteArray getQuicVersion() {
        return quicVersion;
    }
}
