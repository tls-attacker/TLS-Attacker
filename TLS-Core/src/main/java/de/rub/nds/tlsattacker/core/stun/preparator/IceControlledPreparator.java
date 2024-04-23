package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.stun.model.IceControlledAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class IceControlledPreparator extends StunAttributePreparator<IceControlledAttribute>{

    public IceControlledPreparator(Chooser chooser, IceControlledAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setTieBreaker(chooser.getConfig().getIceConfig().getDefaultTieBreaker());
    }
    
}
