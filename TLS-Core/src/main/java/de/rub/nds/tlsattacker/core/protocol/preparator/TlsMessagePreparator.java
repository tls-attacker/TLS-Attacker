/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class TlsMessagePreparator<MessageT extends TlsMessage> extends ProtocolMessagePreparator<MessageT> {

    public TlsMessagePreparator(Chooser chooser, MessageT message) {
        super(chooser, message);
    }
}
