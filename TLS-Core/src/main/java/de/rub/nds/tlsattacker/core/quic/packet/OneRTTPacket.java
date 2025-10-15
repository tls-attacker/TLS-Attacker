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
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A 1-RTT packet uses a short packet header. It is used after the version and 1-RTT keys are
 * negotiated.
 */
@XmlRootElement
public class OneRTTPacket extends QuicPacket {

    private static final Logger LOGGER = LogManager.getLogger();

    public OneRTTPacket() {
        super(QuicPacketType.ONE_RTT_PACKET);
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
        offsetToPacketNumber = 0;
        unprotectedHeaderHelper.reset();

        unprotectedHeaderHelper.write(unprotectedFlags.getValue());
        offsetToPacketNumber++;

        unprotectedHeaderHelper.write(destinationConnectionId.getValue());
        offsetToPacketNumber += destinationConnectionIdLength.getValue();

        unprotectedHeaderHelper.writeBytes(getUnprotectedPacketNumber().getValue());
        offsetToPacketNumber += getUnprotectedPacketNumber().getValue().length;

        completeUnprotectedHeader =
                ModifiableVariableFactory.safelySetValue(
                        completeUnprotectedHeader, unprotectedHeaderHelper.toByteArray());
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
    public OneRTTPacketHandler getHandler(Context context) {
        return new OneRTTPacketHandler(context.getQuicContext());
    }

    @Override
    public OneRTTPacketSerializer getSerializer(Context context) {
        return new OneRTTPacketSerializer(this);
    }

    @Override
    public OneRTTPacketPreparator getPreparator(Context context) {
        return new OneRTTPacketPreparator(context.getChooser(), this);
    }

    @Override
    public OneRTTPacketParser getParser(Context context, InputStream stream) {
        return new OneRTTPacketParser(stream, context.getQuicContext());
    }
}
