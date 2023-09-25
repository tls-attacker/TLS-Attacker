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
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.handler.packet.RetryPacketHandler;
import de.rub.nds.tlsattacker.core.quic.parser.packet.RetryPacketParser;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * A Retry packet carries an address validation token created by the server. It is used by a server
 * that wishes to perform a retry
 */
@XmlRootElement
public class RetryPacket extends LongHeaderPacket<RetryPacket> {

    /** An opaque token that the server can use to validate the client's address. */
    @ModifiableVariableProperty protected ModifiableByteArray retryToken;

    /**
     * Retry packets (see Section 17.2.5 of [QUIC-TRANSPORT]) carry a Retry Integrity Tag that
     * provides two properties: it allows the discarding of packets that have accidentally been
     * corrupted by the network, and only an entity that observes an Initial packet can send a valid
     * Retry packet.
     */
    @ModifiableVariableProperty protected ModifiableByteArray retryIntegrityTag;

    public RetryPacket() {
        super(QuicPacketType.RETRY_PACKET);
        // TODO this does also not match the header set in QuicPacketType
        this.setUnprotectedFlags((byte) 0x3c);
    }

    public RetryPacket(byte flags) {
        super(QuicPacketType.RETRY_PACKET);
        this.setProtectedFlags(flags);
        protectedHeaderHelper.write(flags);
    }

    @Override
    public RetryPacketHandler getHandler(QuicContext context) {
        return new RetryPacketHandler(context);
    }

    @Override
    public Serializer<RetryPacket> getSerializer(QuicContext context) {
        return null;
    }

    @Override
    public Preparator<RetryPacket> getPreparator(QuicContext context) {
        return null;
    }

    @Override
    public RetryPacketParser getParser(QuicContext context, InputStream stream) {
        return new RetryPacketParser(stream, context);
    }

    public ModifiableByteArray getRetryToken() {
        return retryToken;
    }

    public void setRetryToken(byte[] retryToken) {
        this.retryToken = ModifiableVariableFactory.safelySetValue(this.retryToken, retryToken);
    }

    public ModifiableByteArray getRetryIntegrityTag() {
        return retryIntegrityTag;
    }

    public void setRetryIntegrityTag(byte[] retryIntegrityTag) {
        this.retryIntegrityTag =
                ModifiableVariableFactory.safelySetValue(this.retryIntegrityTag, retryIntegrityTag);
    }
}
