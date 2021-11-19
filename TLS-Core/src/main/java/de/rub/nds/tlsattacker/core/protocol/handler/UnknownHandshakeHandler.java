/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.protocol.message.UnknownHandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownHandshakeParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownHandshakePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownHandshakeSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class UnknownHandshakeHandler extends HandshakeMessageHandler<UnknownHandshakeMessage> {

    public UnknownHandshakeHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(UnknownHandshakeMessage message) {
        // nothing to adjust here
    }

}
