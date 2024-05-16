package de.rub.nds.tlsattacker.core.ice.preparator;

import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ChannelDataMessagePreparator extends IceMessagePreparator<ChannelDataMessage> {

    public ChannelDataMessagePreparator(Chooser chooser, ChannelDataMessage object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }
    
}
