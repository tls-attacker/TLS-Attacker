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
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.constants.MiscRfcConstants;
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class QuicPacket extends ModifiableVariableHolder implements DataContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    protected QuicPacketType packetType;

    protected ModifiableByte protectedFlags;
    protected ModifiableByte unprotectedFlags;

    protected ModifiableByteArray destinationConnectionId;
    protected ModifiableByte destinationConnectionIdLength;

    protected ModifiableInteger packetLength;
    protected int packetLengthSize;

    protected ModifiableByteArray protectedPacketNumber;
    protected ModifiableByteArray unprotectedPacketNumber;
    protected ModifiableByteArray restoredPacketNumber;
    protected int plainPacketNumber;
    protected ModifiableInteger packetNumberLength;

    protected ModifiableByteArray protectedPacketNumberAndPayload;
    protected ModifiableByteArray unprotectedPayload;
    protected ModifiableByteArray protectedPayload;

    public ModifiableByteArray completeUnprotectedHeader;
    public ByteArrayOutputStream protectedHeaderHelper = new ByteArrayOutputStream();
    public ByteArrayOutputStream unprotectedHeaderHelper = new ByteArrayOutputStream();

    protected QuicCryptoSecrets packetSecret;
    public int offsetToPacketNumber;
    protected int padding;

    public QuicPacket() {}

    public QuicPacket(QuicPacketType packetType) {
        this.packetType = packetType;
        this.offsetToPacketNumber = 0;
        this.padding = 0;
    }

    public abstract void buildUnprotectedPacketHeader();

    public abstract void convertCompleteProtectedHeader();

    @Override
    public abstract Handler<? extends QuicPacket> getHandler(Context context);

    @Override
    public abstract Serializer<? extends QuicPacket> getSerializer(Context context);

    @Override
    public abstract Preparator<? extends QuicPacket> getPreparator(Context context);

    @Override
    public abstract Parser<? extends QuicPacket> getParser(Context context, InputStream stream);

    public byte[] encodePacketNumber(long packetnumber) {
        if (packetnumber <= 0xff) {
            return new byte[] {(byte) packetnumber};
        } else if (packetnumber <= 0xffff) {
            return new byte[] {(byte) (packetnumber >> 8), (byte) (packetnumber & 0x00ff)};
        } else if (packetnumber <= 0xffffff) {
            return new byte[] {
                (byte) (packetnumber >> 16),
                (byte) (packetnumber >> 8),
                (byte) (packetnumber & 0x00ff)
            };
        } else if (packetnumber <= 0xffffffffL) {
            return new byte[] {
                (byte) (packetnumber >> 24),
                (byte) (packetnumber >> 16),
                (byte) (packetnumber >> 8),
                (byte) (packetnumber & 0x00ff)
            };
        }
        return new byte[] {0};
    }

    public long decodePacketNumber(
            long truncatedPacketnumber, long largestPacketnumber, int packetnumberNBits) {
        long expectedPacketnumber = largestPacketnumber + 1;
        long packetnumberWin = 1L << packetnumberNBits;
        long packetnumberHwin = packetnumberWin / 2;
        long packetnumberMask = ~(packetnumberWin - 1);
        long candidatePacketnumber =
                (expectedPacketnumber & packetnumberMask) | truncatedPacketnumber;

        // See RFC 9000 A.3
        if (candidatePacketnumber <= expectedPacketnumber - packetnumberHwin
                && candidatePacketnumber < (1 << 62) - packetnumberWin) {
            return candidatePacketnumber + packetnumberWin;
        }
        if (candidatePacketnumber > expectedPacketnumber + packetnumberHwin
                && candidatePacketnumber >= packetnumberWin) {
            return candidatePacketnumber - packetnumberWin;
        }
        return candidatePacketnumber;
    }

    protected byte encodePacketNumberLength(byte flags, byte[] packetNumber) throws Exception {
        if (packetNumber.length <= 1) {
            return flags;
        } else if (packetNumber.length <= 2) {
            return (byte) (flags | 0x01);
        } else if (packetNumber.length <= 3) {
            return (byte) (flags | 0x02);
        } else if (packetNumber.length <= 4) {
            return (byte) (flags | 0x03);
        } else {
            throw new Exception("Packetnumber > 4 Byte ist not supported yet");
        }
    }

    public void updateFlagsWithEncodedPacketNumber() {
        try {
            setUnprotectedFlags(
                    encodePacketNumberLength(
                            unprotectedFlags.getValue(), unprotectedPacketNumber.getValue()));
        } catch (Exception e) {
            LOGGER.error(e);
        }
    }

    /**
     * The sample of ciphertext is taken starting from an offset of 4 bytes after the start of the
     * Packet Number field. That is, in sampling packet ciphertext for header protection, the Packet
     * Number field is assumed to be 4 bytes long (its maximum possible encoded length).
     *
     * <p>As we already have the payload as separate byte array we need to adjust the offset to be 4
     * minus the actual length of the packet number.
     *
     * <p>Pseudocode: # pn_offset is the start of the Packet Number field. sample_offset = pn_offset
     * + 4
     *
     * <p>sample = packet[sample_offset..sample_offset+sample_length]
     *
     * @return header protection sample as byte array
     */
    public byte[] getHeaderProtectionSample() {
        byte[] sample = new byte[16];
        if (protectedPayload != null) {
            System.arraycopy(
                    protectedPayload.getValue(),
                    MiscRfcConstants.MAX_ENCODED_PACKETNUMBER_LENGTH
                            - packetNumberLength.getValue(),
                    sample,
                    0,
                    16);
        } else {
            System.arraycopy(
                    protectedPacketNumberAndPayload.getValue(),
                    MiscRfcConstants.MAX_ENCODED_PACKETNUMBER_LENGTH,
                    sample,
                    0,
                    16);
        }

        return sample;
    }

    @Override
    public String toCompactString() {
        return this.packetType.getName();
    }

    public void setProtectedFlags(byte protectedFlags) {
        this.protectedFlags =
                ModifiableVariableFactory.safelySetValue(this.protectedFlags, protectedFlags);
    }

    public void setProtectedFlags(ModifiableByte protectedFlags) {
        this.protectedFlags = protectedFlags;
    }

    public void setUnprotectedFlags(byte unprotectedFlags) {
        this.unprotectedFlags =
                ModifiableVariableFactory.safelySetValue(this.unprotectedFlags, unprotectedFlags);
    }

    public void setUnprotectedFlags(ModifiableByte unprotectedFlags) {
        this.unprotectedFlags = unprotectedFlags;
    }

    public void setPacketNumberLength(int packetNumberLength) {
        this.packetNumberLength =
                ModifiableVariableFactory.safelySetValue(
                        this.packetNumberLength, packetNumberLength);
    }

    public void setPacketNumberLength(ModifiableInteger packetNumberLength) {
        this.packetNumberLength = packetNumberLength;
    }

    public void setProtectedPacketNumber(byte[] packetNumber) {
        this.protectedPacketNumber =
                ModifiableVariableFactory.safelySetValue(this.protectedPacketNumber, packetNumber);
    }

    public void setProtectedPacketNumber(ModifiableByteArray packetNumber) {
        this.protectedPacketNumber = packetNumber;
    }

    public void setPacketLengthSize(int packetLengthSize) {
        this.packetLengthSize = packetLengthSize;
    }

    public void setUnprotectedPacketNumber(byte[] packetNumber) {
        setPacketNumberLength(packetNumber.length);
        this.unprotectedPacketNumber =
                ModifiableVariableFactory.safelySetValue(
                        this.unprotectedPacketNumber, packetNumber);
    }

    public void setUnprotectedPacketNumber(ModifiableByteArray packetNumber) {
        setPacketNumberLength(packetNumber.getValue().length);
        this.unprotectedPacketNumber = packetNumber;
    }

    public void setUnprotectedPacketNumber(int packetNumber) {
        this.setUnprotectedPacketNumber(encodePacketNumber(packetNumber));
    }

    public void setRestoredPacketNumber(byte[] packetNumber) {
        this.restoredPacketNumber =
                ModifiableVariableFactory.safelySetValue(this.restoredPacketNumber, packetNumber);
    }

    public void setRestoredPacketNumber(ModifiableByteArray packetNumber) {
        this.restoredPacketNumber = packetNumber;
    }

    public void setRestoredPacketNumber(int packetNumber) {
        this.setRestoredPacketNumber(encodePacketNumber(packetNumber));
    }

    public void setPacketLength(int packetLength) {
        this.packetLength =
                ModifiableVariableFactory.safelySetValue(this.packetLength, packetLength);
    }

    public void setRestoredPacketNumber(ModifiableInteger packetLength) {
        this.packetLength = packetLength;
    }

    public void setDestinationConnectionId(byte[] destinationConnectionId) {
        this.destinationConnectionId =
                ModifiableVariableFactory.safelySetValue(
                        this.destinationConnectionId, destinationConnectionId);
    }

    public void setDestinationConnectionId(ModifiableByteArray destinationConnectionId) {
        this.destinationConnectionId = destinationConnectionId;
    }

    public void setDestinationConnectionIdLength(byte destinationConnectionIdLength) {
        this.destinationConnectionIdLength =
                ModifiableVariableFactory.safelySetValue(
                        this.destinationConnectionIdLength, destinationConnectionIdLength);
    }

    public void setDestinationConnectionIdLength(ModifiableByte destinationConnectionIdLength) {
        this.destinationConnectionIdLength = destinationConnectionIdLength;
    }

    public void setProtectedPacketNumberAndPayload(byte[] protectedPacketNumberAndPayload) {
        this.protectedPacketNumberAndPayload =
                ModifiableVariableFactory.safelySetValue(
                        this.protectedPacketNumberAndPayload, protectedPacketNumberAndPayload);
    }

    public void setProtectedPacketNumberAndPayload(
            ModifiableByteArray protectedPacketNumberAndPayload) {
        this.protectedPacketNumberAndPayload = protectedPacketNumberAndPayload;
    }

    public void setUnprotectedPayload(byte[] unprotectedPayload) {
        this.unprotectedPayload =
                ModifiableVariableFactory.safelySetValue(
                        this.unprotectedPayload, unprotectedPayload);
    }

    public void setUnprotectedPayload(ModifiableByteArray unprotectedPayload) {
        this.unprotectedPayload = unprotectedPayload;
    }

    public void setProtectedPayload(byte[] protectedPayload) {
        this.protectedPayload =
                ModifiableVariableFactory.safelySetValue(this.protectedPayload, protectedPayload);
    }

    public void setProtectedPayload(ModifiableByteArray protectedPayload) {
        this.protectedPayload = protectedPayload;
    }

    public void setPacketSecret(QuicCryptoSecrets packetSecret) {
        this.packetSecret = packetSecret;
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public void setPlainPacketNumber(int plainPacketNumber) {
        this.plainPacketNumber = plainPacketNumber;
    }

    public ModifiableByte getProtectedFlags() {
        return protectedFlags;
    }

    public QuicPacketType getPacketType() {
        return packetType;
    }

    public ModifiableByte getUnprotectedFlags() {
        return unprotectedFlags;
    }

    public ModifiableByteArray getUnprotectedPacketNumber() {
        return unprotectedPacketNumber;
    }

    public ModifiableInteger getPacketNumberLength() {
        return packetNumberLength;
    }

    public ModifiableByteArray getProtectedPacketNumber() {
        return protectedPacketNumber;
    }

    public ModifiableByteArray getRestoredPacketNumber() {
        return restoredPacketNumber;
    }

    public int getPacketLengthSize() {
        return packetLengthSize;
    }

    public ModifiableInteger getPacketLength() {
        return packetLength;
    }

    public ModifiableByteArray getDestinationConnectionId() {
        return destinationConnectionId;
    }

    public ModifiableByte getDestinationConnectionIdLength() {
        return destinationConnectionIdLength;
    }

    public ModifiableByteArray getProtectedPacketNumberAndPayload() {
        return protectedPacketNumberAndPayload;
    }

    public ModifiableByteArray getUnprotectedPayload() {
        return unprotectedPayload;
    }

    public ModifiableByteArray getProtectedPayload() {
        return protectedPayload;
    }

    public int getPlainPacketNumber() {
        return plainPacketNumber;
    }

    public int getPadding() {
        return padding;
    }
}
