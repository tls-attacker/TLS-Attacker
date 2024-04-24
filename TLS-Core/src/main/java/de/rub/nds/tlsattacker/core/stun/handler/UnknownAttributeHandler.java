package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;

public class UnknownAttributeHandler extends StunAttributeHandler<UnknownAttribute> {

    public UnknownAttributeHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(UnknownAttribute container) {
        //Todo nothing to do here
    }
    
}
