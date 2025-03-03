package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DisableTLSLayersAction extends ConnectionBoundAction {
    DisableLayerAction disableLayersAction = new DisableLayerAction(ImplementedLayers.MESSAGE, ImplementedLayers.RECORD);
    @Override
    public void execute(State state) throws ActionExecutionException {
        disableLayersAction.execute(state);
        setExecuted(true);
    }

    @Override
    public void reset() {
        disableLayersAction.reset();
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return disableLayersAction.executedAsPlanned();
    }
}
