package de.rub.nds.tlsattacker.core.layer;

import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class LayerStackFactory {

    public static LayerStack createLayerStack(LayerStackType type, TlsContext context) {

        switch (type) {
            case DTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case OPEN_VPN:
                throw new UnsupportedOperationException("Not implemented yet");
            case QUIC:
                throw new UnsupportedOperationException("Not implemented yet");
            case STARTTTLS:
                throw new UnsupportedOperationException("Not implemented yet");
            case TLS:
                return new LayerStack(new RecordLayer(context), new TcpLayer(null));//TODO init socket
            default:
                throw new RuntimeException("Unknown LayerStackType: " + type.name());
        }
    }
}
