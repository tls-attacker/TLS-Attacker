package de.rub.nds.tlsattacker.core.ice.preparator;

import de.rub.nds.tlsattacker.core.ice.model.IceMessage;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class IceMessagePreparator <MessageT extends IceMessage>
        extends Preparator<MessageT>{

    public IceMessagePreparator(Chooser chooser, MessageT object) {
        super(chooser, object);
    }
    
}
