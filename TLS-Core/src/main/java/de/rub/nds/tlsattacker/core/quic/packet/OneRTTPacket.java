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
import de.rub.nds.tlsattacker.core.quic.constants.QuicCryptoSecrets;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.OneRTTPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.OneRTTPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.OneRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.OneRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.IOException;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A 1-RTT packet uses a short packet header. It is used after the version and 1-RTT keys are
 * negotiated.
 */
@XmlRootElement
public class OneRTTPacket extends QuicPacket<OneRTTPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    public OneRTTPacket() {
        super(QuicPacketType.ONE_RTT_PACKET);
        // TODO: this does not match the header set in QuickPacketType
        this.setUnprotectedFlags((byte) 0x40);
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    public OneRTTPacket(byte flags) {
        super(QuicPacketType.ONE_RTT_PACKET);
        this.setProtectedFlags((byte) flags);
        protectedHeaderHelper.write(flags);
        this.packetSecret = QuicCryptoSecrets.APPLICATION_SECRET;
    }

    @Override
    public void buildUnprotectedPacketHeader() {
        try {
            unprotectedHeaderHelper.write(unprotectedFlags.getValue());
            offsetToPacketNumber++;

            unprotectedHeaderHelper.write(destinationConnectionId.getValue());
            offsetToPacketNumber += destinationConnectionIdLength.getValue();

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
        offsetToPacketNumber = 1 + destinationConnectionId.getValue().length;

        this.completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(
                        this.completeUnprotectedHeader, protectedHeaderBytes);
    }

    @Override
    public OneRTTPacketHandler getHandler(QuicContext context) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public OneRTTPacketSerializer getSerializer(QuicContext context) {
        return new OneRTTPacketSerializer(this);
    }

    @Override
    public OneRTTPacketPreparator getPreparator(QuicContext context) {
        return new OneRTTPacketPreparator(context.getChooser(), this);
    }

    @Override
    public OneRTTPacketParser getParser(QuicContext context, InputStream stream) {
        return new OneRTTPacketParser(stream, context);
    }
}
