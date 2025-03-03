package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.impl.ToggleableLayerWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DisableLayerAction extends ToggleLayerAction {
    public DisableLayerAction(ImplementedLayers... targetedLayers) {
        super(targetedLayers);
    }

    public DisableLayerAction() {
        //JAXB
        super();
    }
    @Override
    protected void updateLayerState(ToggleableLayerWrapper<?, ?> layerWrapper) {
        layerWrapper.setActive(false);
    }
}
