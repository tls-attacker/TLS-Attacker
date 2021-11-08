
package de.rub.nds.tlsattacker.core.layer;

import java.util.List;

public class LayerProcessingResult<T extends DataContainer> {

    private List<T> usedContainers;

    private byte[] resultingData;

    public LayerProcessingResult(List<T> usedContainers, byte[] resultingData) {
        this.usedContainers = usedContainers;
        this.resultingData = resultingData;
    }

    public List<T> getUsedContainers() {
        return usedContainers;
    }

    public void setUsedContainers(List<T> usedContainers) {
        this.usedContainers = usedContainers;
    }

    public byte[] getResultingData() {
        return resultingData;
    }

    public void setResultingData(byte[] resultingData) {
        this.resultingData = resultingData;
    }
}
