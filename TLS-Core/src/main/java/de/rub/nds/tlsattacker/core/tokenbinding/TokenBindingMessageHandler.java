/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.tokenbinding;

import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;

public class TokenBindingMessageHandler extends TlsMessageHandler<TokenBindingMessage> {

    public TokenBindingMessageHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSContext(TokenBindingMessage message) {

    }

}
