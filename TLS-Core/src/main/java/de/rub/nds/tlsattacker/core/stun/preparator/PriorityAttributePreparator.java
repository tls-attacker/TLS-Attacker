package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.stun.model.PriorityAttribute;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class PriorityAttributePreparator extends StunAttributePreparator<PriorityAttribute> {

    public PriorityAttributePreparator(Chooser chooser, PriorityAttribute attribute) {
        super(chooser, attribute);
    }

    @Override
    public void prepareContent() {
        getObject().setPriority(chooser.getContext().getIceContext().getStunPriority());
    }
}
