/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import java.io.InputStream;

import de.rub.nds.tlsattacker.core.layer.DataContainer;

public abstract class ProtocolMessageParser<Message extends DataContainer> extends Parser<Message> {

    public ProtocolMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public final void parse(Message message) {
        parseMessageContent(message);
    }

    protected abstract void parseMessageContent(Message message);
}
