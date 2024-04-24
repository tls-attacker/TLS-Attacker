package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.stun.model.UnknownAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class UnknownAttributePreparator extends StunAttributePreparator<UnknownAttribute> {

    public UnknownAttributePreparator(Chooser chooser, UnknownAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setUnknownContent(new byte[0]);
    }
    
}
