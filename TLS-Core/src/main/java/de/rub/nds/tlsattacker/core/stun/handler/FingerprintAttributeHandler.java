package de.rub.nds.tlsattacker.core.stun.handler;

import de.rub.nds.tlsattacker.core.stun.IceContext;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;

public class FingerprintAttributeHandler extends StunAttributeHandler<FingerprintAttribute> {

    public FingerprintAttributeHandler(IceContext context) {
        super(context);
    }

    @Override
    public void adjustContext(FingerprintAttribute container) {
        // Nothing to do
    }
    
}
