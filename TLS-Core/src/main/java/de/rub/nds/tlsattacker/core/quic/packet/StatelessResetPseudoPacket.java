/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.packet;

import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;
import org.apache.commons.lang3.NotImplementedException;

/**
 * Pseudo Packet class to include Stateless Resets in the Workflow Trace. We do not intend to
 * send them. They are and have to be specially handled in the packet layer as the normal
 * process of handling packets (e.g., decrypting and parsing) does not apply to them.
 */
public class StatelessResetPseudoPacket extends QuicPacket {

    public StatelessResetPseudoPacket() {
        super(QuicPacketType.STATELESS_RESET);
    }

    @Override
    public void buildUnprotectedPacketHeader() {
        throw new NotImplementedException();
    }

    @Override
    public void convertCompleteProtectedHeader() {
        throw new NotImplementedException();
    }

    @Override
    public Handler<? extends QuicPacket> getHandler(Context context) {
        throw new NotImplementedException();
    }

    @Override
    public Serializer<? extends QuicPacket> getSerializer(Context context) {
        throw new NotImplementedException();
    }

    @Override
    public Preparator<? extends QuicPacket> getPreparator(Context context) {
        throw new NotImplementedException();
    }

    @Override
    public Parser<? extends QuicPacket> getParser(Context context, InputStream stream) {
        throw new NotImplementedException();
    }
}
