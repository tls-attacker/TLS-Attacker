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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.quic.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.InitialPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.InitialPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.InitialPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.InitialPacketSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An Initial packet uses long headers with a type value of 0x00. It carries the first CRYPTO frames
 * sent by the client and server to perform key exchange, and it carries ACK frames in either
 * direction.
 */
@XmlRootElement
public class InitialPacket extends LongHeaderPacket {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * A variable-length integer specifying the length of the Token field, in bytes. This value is 0
     * if no token is present. Initial packets sent by the server MUST set the Token Length field to
     * 0; clients that receive an Initial packet with a non-zero Token Length field MUST either
     * discard the packet or generate a connection error of type PROTOCOL_VIOLATION.
     */
    @ModifiableVariableProperty protected ModifiableInteger tokenLength;

    /**
     * The value of the token that was previously provided in a Retry packet or NEW_TOKEN frame; see
     * Section 8.1.
     */
    @ModifiableVariableProperty protected ModifiableByteArray token;

    public int tokenLengthSize;

    public InitialPacket() {
        super(QuicPacketType.INITIAL_PACKET);
        this.packetSecret = QuicCryptoSecrets.INITIAL_SECRET;
    }

    public InitialPacket(byte flags, byte[] versionBytes) {
        super(QuicPacketType.INITIAL_PACKET);
        this.setProtectedFlags(flags);
        protectedHeaderHelper.write(flags);
        this.packetSecret = QuicCryptoSecrets.INITIAL_SECRET;
        setQuicVersion(versionBytes);
        try {
            protectedHeaderHelper.write(versionBytes);
        } catch (IOException e) {
            LOGGER.error(e);
        }
    }

    public void setToken(ModifiableByteArray token) {
        this.token = token;
    }

    public void setToken(byte[] array) {
        this.token = ModifiableVariableFactory.safelySetValue(this.token, array);
    }

    public void setTokenLength(ModifiableInteger tokenLength) {
        this.tokenLength = tokenLength;
        this.tokenLengthSize =
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(tokenLength.getValue())
                        .length;
    }

    public void setTokenLength(int length) {
        this.tokenLength = ModifiableVariableFactory.safelySetValue(this.tokenLength, length);
        this.tokenLengthSize =
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(length).length;
    }

    public void setTokenLengthSize(int size) {
        this.tokenLengthSize = size;
    }

    public ModifiableByteArray getToken() {
        return token;
    }

    public ModifiableInteger getTokenLength() {
        return tokenLength;
    }

    public int getTokenLengthSize() {
        return tokenLengthSize;
    }

    @Override
    public InitialPacketHandler getHandler(QuicContext context) {
        return new InitialPacketHandler(context);
    }

    @Override
    public InitialPacketSerializer getSerializer(QuicContext context) {
        return new InitialPacketSerializer(this);
    }

    @Override
    public InitialPacketPreparator getPreparator(QuicContext context) {
        return new InitialPacketPreparator(context.getChooser(), this);
    }

    @Override
    public InitialPacketParser getParser(QuicContext context, InputStream stream) {
        return new InitialPacketParser(stream, context);
    }

    @Override
    public void convertCompleteProtectedHeader() {
        // InitialPacket Header: Protected Flags + Version + DCID Length + DCID + SCID Length + SCID
        // + Token Length +
        // Token +
        // Offset to Protected Packet Number
        // [1 Byte] + [4 Byte] + [1 Byte] + [..] + [1 Byte] + [..] + [VLIE] + [..] + [1-4 Bytes]

        byte[] r = protectedHeaderHelper.toByteArray();
        r[0] = unprotectedFlags.getValue();
        offsetToPacketNumber =
                QuicPacketByteLength.QUIC_FIRST_HEADER_BYTE
                        + QuicPacketByteLength.QUIC_VERSION_LENGTH
                        + QuicPacketByteLength.DESTINATION_CONNECTION_ID_LENGTH
                        + destinationConnectionId.getValue().length
                        + QuicPacketByteLength.SOURCE_CONNECTION_ID_LENGTH
                        + sourceConnectionId.getValue().length
                        + tokenLengthSize
                        + token.getValue().length
                        + packetLengthSize;

        this.completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(this.completeUnprotectedHeader, r);
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

            byte[] tokenLengthBytes =
                    VariableLengthIntegerEncoding.encodeVariableLengthInteger(
                            tokenLength.getValue());
            unprotectedHeaderHelper.write(tokenLengthBytes);
            offsetToPacketNumber += tokenLengthBytes.length;

            if (tokenLength.getValue() > 0) {
                unprotectedHeaderHelper.write(token.getValue());
                offsetToPacketNumber += token.getValue().length;
            }

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
}
