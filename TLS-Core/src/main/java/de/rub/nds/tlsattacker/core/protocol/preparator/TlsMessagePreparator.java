package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class TlsMessagePreparator<MessageT extends TlsMessage> extends ProtocolMessagePreparator<MessageT> {

    public TlsMessagePreparator(Chooser chooser, MessageT message) {
        super(chooser, message);
    }
}
