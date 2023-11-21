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

/**
 * Long headers are used for packets that are sent prior to the establishment of 1-RTT keys. Once
 * 1-RTT keys are available, a sender switches to sending packets using the short header (Section
 * 17.3). The long form allows for special packets -- such as the Version Negotiation packet -- to
 * be represented in this uniform fixed-length packet format.
 *
 * @param <T>
 */
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

    /**
     * The QUIC Version is a 32-bit field that follows the first byte. This field indicates the
     * version of QUIC that is in use and determines how the rest of the protocol fields are
     * interpreted.
     */
    @ModifiableVariableProperty protected ModifiableByteArray quicVersion;

    /**
     * The byte following the Destination Connection ID contains the length in bytes of the Source
     * Connection ID field that follows it. This length is encoded as an 8-bit unsigned integer.
     */
    @ModifiableVariableProperty protected ModifiableByte sourceConnectionIdLength;

    /**
     * The Source Connection ID field follows the Source Connection ID Length field, which indicates
     * the length of this field.
     */
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

            byte[] pL =
                    VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                            packetLength.getValue());
            unprotectedHeaderHelper.write(pL);
            offsetToPacketNumber += pL.length;

            unprotectedHeaderHelper.writeBytes(getUnprotectedPacketNumber().getValue());
            offsetToPacketNumber += getUnprotectedPacketNumber().getValue().length;

            completeUnprotectedHeader =
                    ModifiableVariableFactory.safelySetValue(
                            completeUnprotectedHeader, unprotectedHeaderHelper.toByteArray());

        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    public void convertCompleteProtectedHeader() {
        // Header: Protected Flags + Version + DCID Length + DCID + SCID Length + SCID + Protected
        // Packet Number
        // [1 Byte] + [4 Byte] + [1 Byte] + [..] + [1 Byte] + [..] + [1-4 Bytes]

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

    public void setSourceConnectionId(byte[] sourceConnectionId) {
        this.sourceConnectionId =
                ModifiableVariableFactory.safelySetValue(
                        this.sourceConnectionId, sourceConnectionId);
    }

    public void setSourceConnectionIdLength(byte variableLengthInteger) {
        this.sourceConnectionIdLength =
                ModifiableVariableFactory.safelySetValue(
                        this.sourceConnectionIdLength, variableLengthInteger);
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
