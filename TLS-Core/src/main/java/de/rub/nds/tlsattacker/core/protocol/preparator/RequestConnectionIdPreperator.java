/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.RequestConnectionIdMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class RequestConnectionIdPreperator
        extends HandshakeMessagePreparator<RequestConnectionIdMessage> {

    public RequestConnectionIdPreperator(Chooser chooser, RequestConnectionIdMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        // nothing to do here, since this message has to be constructed by hand
    }
}
