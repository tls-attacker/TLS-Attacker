/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.parser.DtlsHandshakeMessageFragmentParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.DtlsHandshakeMessageFragmentPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class DtlsHandshakeMessageFragmentHandler extends HandshakeMessageHandler<DtlsHandshakeMessageFragment> {

    public DtlsHandshakeMessageFragmentHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public DtlsHandshakeMessageFragmentParser getParser(byte[] message, int pointer) {
        return new DtlsHandshakeMessageFragmentParser(pointer, message,
            tlsContext.getChooser().getSelectedProtocolVersion(), tlsContext.getConfig());
    }

    @Override
    public DtlsHandshakeMessageFragmentPreparator getPreparator(DtlsHandshakeMessageFragment message) {
        return new DtlsHandshakeMessageFragmentPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public DtlsHandshakeMessageFragmentSerializer getSerializer(DtlsHandshakeMessageFragment message) {
        return new DtlsHandshakeMessageFragmentSerializer(message,
            tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(DtlsHandshakeMessageFragment message) {
    }
}
