package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;

public class MessageIntegrityHandler extends StunAttributeHandler<MessageIntegrityAttribute> {

    public MessageIntegrityHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(MessageIntegrityAttribute container) {
        // Nothing to do
    }
    
}
