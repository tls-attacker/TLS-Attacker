/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.state.Context;

public abstract class AcknowledgingProtocolLayer<
                ContextType extends Context,
                Hint extends LayerProcessingHint,
                Container extends DataContainer<Context>>
        extends ProtocolLayer<ContextType, Hint, Container> {

    public AcknowledgingProtocolLayer(LayerType layerType) {
        super(layerType);
    }

    public abstract void sendAck(byte[] data);
}
