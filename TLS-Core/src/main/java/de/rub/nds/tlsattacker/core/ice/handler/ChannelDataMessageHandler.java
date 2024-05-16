package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.StunMessage;

public class ChannelDataMessageHandler extends IceMessageHandler<StunMessage> {

    public ChannelDataMessageHandler() {
    }

    @Override
    public void adjustContext(StunMessage container) {
        // Nothing to do here
    }
    
}
