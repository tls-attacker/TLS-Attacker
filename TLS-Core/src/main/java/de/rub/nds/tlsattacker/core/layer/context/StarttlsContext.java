/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
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
