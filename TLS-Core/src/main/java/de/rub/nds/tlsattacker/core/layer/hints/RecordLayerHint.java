
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
