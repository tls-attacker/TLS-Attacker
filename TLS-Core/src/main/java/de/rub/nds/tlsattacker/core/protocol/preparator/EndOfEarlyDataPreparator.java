/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.EndOfEarlyDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EndOfEarlyDataPreparator extends HandshakeMessagePreparator<EndOfEarlyDataMessage> {

    public EndOfEarlyDataPreparator(Chooser chooser, EndOfEarlyDataMessage message) {
        super(chooser, message);
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        // EndOfEarlyData is always empty
    }

}
