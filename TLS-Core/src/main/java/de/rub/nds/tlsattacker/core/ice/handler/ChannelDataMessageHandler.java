package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.ChannelDataMessage;

public class ChannelDataMessageHandler extends IceMessageHandler<ChannelDataMessage> {

    public ChannelDataMessageHandler() {
    }

    @Override
    public void adjustContext(ChannelDataMessage container) {
        // Nothing to do here
    }
    
}
