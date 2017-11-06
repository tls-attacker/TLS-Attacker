/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * An arbitrary protocol message
 * 

 */
@XmlRootElement
public class ArbitraryMessage extends ProtocolMessage {

    public ArbitraryMessage() {
        super();
    }

    @Override
    public boolean isRequired() {
        return false;
    }

    @Override
    public String toCompactString() {
        return "ARBITRARY PROTOCOL MESSAGE";
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        throw new UnsupportedOperationException("Cannot retrieve Handler this way"); // To
                                                                                     // change
                                                                                     // body
                                                                                     // of
                                                                                     // generated
                                                                                     // methods,
                                                                                     // choose
                                                                                     // Tools
                                                                                     // |
                                                                                     // Templates.
    }
}
