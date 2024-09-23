package de.rub.nds.tlsattacker.core.layer.context;

import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.Context;

public class StarttlsContext extends LayerContext {
    public MessageLayer getMessageLayer() {
        return messageLayer;
    }

    public void setMessageLayer(MessageLayer messageLayer) {
        this.messageLayer = messageLayer;
    }

    MessageLayer messageLayer;

    public RecordLayer getRecordLayer() {
        return recordLayer;
    }

    public void setRecordLayer(RecordLayer recordLayer) {
        this.recordLayer = recordLayer;
    }

    RecordLayer recordLayer;

    public StarttlsContext(Context context) {
        super(context);
    }

}
