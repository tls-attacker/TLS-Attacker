package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.IceMessage;
import de.rub.nds.tlsattacker.core.layer.data.Handler;

public abstract class IceMessageHandler<MessageT extends IceMessage> extends Handler<MessageT> {
    
}
