package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.impl.ToggleableLayerWrapper;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.util.List;

/**
 * This action toggles the active state of one or multiple toggleable layers.
 * It is designed to be used in conjunction with {@link ToggleableLayerWrapper} and will not execute as planned for layer stacks that do not contain the requested ToggleableLayerWrappers.
 * @see ToggleableLayerWrapper
 * @see de.rub.nds.tlsattacker.core.layer.LayerStack
 */
@XmlRootElement
public class ToggleLayerAction extends ConnectionBoundAction {
    private boolean executedAsPlanned = true;
    // JAXB does not support Interfaces, so we have to use the concrete enum here, which is not ideal
    // we would prefer to use the LayerType interface
    private final List<ImplementedLayers> targetedLayers;

    public ToggleLayerAction() {
        //JAXB
        this.targetedLayers = List.of();
    }
    public ToggleLayerAction(ImplementedLayers... targetedLayers) {
        this.targetedLayers = List.of(targetedLayers);
    }
    @Override
    public void execute(State state) throws ActionExecutionException {
        executedAsPlanned = true;
        for(LayerType layerType : targetedLayers) {
            ProtocolLayer<?,?> layer = state.getContext().getLayerStack().getLayer(layerType);
            if (layer instanceof ToggleableLayerWrapper) {
                updateLayerState((ToggleableLayerWrapper<?, ?>) layer);
            } else {
                // this triggers when a requested layer is not a ToggleableLayerWrapper OR the layer is null (does not even exist)
                executedAsPlanned = false;
            }
        }
        setExecuted(true);
    }

    /**
     * This method is used to update the ToggleableLayerWrapper for different incarnations of ActivateLayerAction to implement.
     */
    protected void updateLayerState(ToggleableLayerWrapper<?, ?> layerWrapper) {
        layerWrapper.setActive(!layerWrapper.isActive());
    }

    /**
     * Checks whether the layers that were supposed to be toggled were able to be found in the layer stack. If not, the action was not executed as planned.
     * It is important to note that this method does not check whether the active layers were actually changed, only whether they were found (i.e. ToggleLayerAction will executed as planned for an already enabled layer).
     * @return true if the action was executed as planned, false otherwise
     */
    @Override
    public boolean executedAsPlanned() {
        return executedAsPlanned;
    }

    /** Rests the executed state of the action */
    @Override
    public void reset() {
        setExecuted(false);
        executedAsPlanned = false;
    }
}
