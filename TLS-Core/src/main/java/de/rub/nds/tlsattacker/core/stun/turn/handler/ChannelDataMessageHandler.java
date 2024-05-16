package de.rub.nds.tlsattacker.core.stun.turn.handler;

import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;

public class ChannelDataMessageHandler extends Handler<StunMessage> {

    public ChannelDataMessageHandler() {
    }

    @Override
    public void adjustContext(StunMessage container) {
        // Nothing to do here
    }
    
}
