package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.IceControlledAttribute;

public class IceControlledHandler extends StunAttributeHandler<IceControlledAttribute> {

    public IceControlledHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(IceControlledAttribute container) {
        context.setTieBreaker(container.getTieBreaker().getValue());
    }
}
