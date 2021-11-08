package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

public class SpecificContainerLayerConfiguration<Container extends DataContainer> extends LayerConfiguration<Container> {

    public SpecificContainerLayerConfiguration(List<Container> containerList) {
        super(containerList);
    }

    public SpecificContainerLayerConfiguration(Container... containers) {
        super(containers);
    }

    @Override
    public boolean isFullfilled(List<Container> list) {
        //TODO Return true if the exact list of the configuration has been received
        return true;
    }

}
