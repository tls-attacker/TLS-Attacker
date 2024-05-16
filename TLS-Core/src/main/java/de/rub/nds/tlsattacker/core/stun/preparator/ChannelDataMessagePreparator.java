package de.rub.nds.tlsattacker.core.stun.preparator;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.stun.model.ChannelDataMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ChannelDataMessagePreparator extends Preparator<ChannelDataMessage> {

    public ChannelDataMessagePreparator(Chooser chooser, ChannelDataMessage object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }
    
}
