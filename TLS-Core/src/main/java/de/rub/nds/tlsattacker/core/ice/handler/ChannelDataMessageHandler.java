package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.layer.data.Handler;

public class ChannelDataMessageHandler extends Handler<StunMessage> {

    public ChannelDataMessageHandler() {
    }

    @Override
    public void adjustContext(StunMessage container) {
        // Nothing to do here
    }
    
}
