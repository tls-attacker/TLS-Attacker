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
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.InitialPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.InitialPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.InitialPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.InitialPacketSerializer;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
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

    @ModifiableVariableProperty protected ModifiableInteger tokenLength;

    @ModifiableVariableProperty protected ModifiableByteArray token;

    public int tokenLengthSize;

    public InitialPacket() {
        super(QuicPacketType.INITIAL_PACKET);
        this.packetSecret = QuicCryptoSecrets.INITIAL_SECRET;
    }

    public InitialPacket(byte[] unprotectedPayload) {
        super(QuicPacketType.INITIAL_PACKET);
        this.packetSecret = QuicCryptoSecrets.INITIAL_SECRET;
        setUnprotectedPayload(unprotectedPayload);
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

    /** In comparison to the {@link LongHeaderPacket}, we add the token here. */
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

    /** In comparison to the {@link LongHeaderPacket}, we add the token here. */
    @Override
    public void convertCompleteProtectedHeader() {
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
        completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(this.completeUnprotectedHeader, r);
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
}
