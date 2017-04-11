/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * An arbitrary protocol message
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
public class ArbitraryMessage extends ProtocolMessage {

    public ArbitraryMessage() {
        super();
        this.setRequired(false);
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
