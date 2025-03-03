package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;

@XmlRootElement
public class EnableTLSLayersAction extends ConnectionBoundAction {
    @XmlTransient
    EnableLayerAction enableLayerAction = new EnableLayerAction(ImplementedLayers.MESSAGE, ImplementedLayers.RECORD);
    @Override
    public void execute(State state) throws ActionExecutionException {
        enableLayerAction.execute(state);
        setExecuted(true);
    }

    @Override
    public void reset() {
        enableLayerAction.reset();
        setExecuted(true);
    }

    @Override
    public boolean executedAsPlanned() {
        return enableLayerAction.executedAsPlanned();
    }
}
