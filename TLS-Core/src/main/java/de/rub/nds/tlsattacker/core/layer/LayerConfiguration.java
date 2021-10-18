package de.rub.nds.tlsattacker.core.layer;

import java.util.Arrays;
import java.util.List;

public class LayerConfiguration<T extends DataContainer> {

    private final List<T> containerList;

    private byte[] additionalLayerData = null;

    public LayerConfiguration(List<T> containerList) {
        this.containerList = containerList;
    }

    public LayerConfiguration(T... containers) {
        this.containerList = Arrays.asList(containers);
    }

    public LayerConfiguration(byte[] additionalLayerData, List<T> containerList) {
        this.containerList = containerList;
        this.additionalLayerData = additionalLayerData;
    }

    public LayerConfiguration(byte[] additionalLayerData, T... containers) {
        this.containerList = Arrays.asList(containers);
        this.additionalLayerData = additionalLayerData;
    }

    public List<T> getContainerList() {
        return containerList;
    }

    public byte[] getAdditionalLayerData() {
        return additionalLayerData;
    }

    public void setAdditionalLayerData(byte[] additionalLayerData) {
        this.additionalLayerData = additionalLayerData;
    }
}
