package de.rub.nds.tlsattacker.core.layer.impl;

import java.io.IOException;

import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;

public class StunTurnLayer extends ProtocolLayer<RecordLayerHint, StunMessage>{

    public StunTurnLayer() {
        super(ImplementedLayers.STUN_TURN);
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'sendConfiguration'");
    }

    @Override
    public LayerProcessingResult sendData(RecordLayerHint hint, byte[] additionalData) throws IOException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'sendData'");
    }

    @Override
    public LayerProcessingResult receiveData() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'receiveData'");
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'receiveMoreDataForHint'");
    }
    
}
