/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.layer.hints;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import java.util.Objects;

public class RecordLayerHint implements LayerProcessingHint {

    private final ProtocolMessageType type;

    public RecordLayerHint(ProtocolMessageType type) {
        this.type = type;
    }

    @Override
    public boolean equals(Object other) {
        if (other instanceof RecordLayerHint) {
            if (this.type == ((RecordLayerHint) other).type) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + Objects.hashCode(this.type);
        return hash;
    }

    public ProtocolMessageType getType() {
        return type;
    }
}
