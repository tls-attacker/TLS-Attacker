package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

public class TillContainerLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container>{

    @Override
    public boolean isFullfilled(List<Container> list) {
        //TODO check that this is fullfilled
        return true;
    }
    
}
