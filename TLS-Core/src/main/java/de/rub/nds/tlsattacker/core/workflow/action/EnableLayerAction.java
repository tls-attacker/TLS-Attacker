package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.impl.ToggleableLayerWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class EnableLayerAction extends ToggleLayerAction {
    public EnableLayerAction(ImplementedLayers... targetedLayers) {
        super(targetedLayers);
    }

    public EnableLayerAction() {
        //JAXB
        super();
    }
    @Override
    protected void updateLayerState(ToggleableLayerWrapper<?, ?> layerWrapper) {
        layerWrapper.setActive(true);
    }
}
