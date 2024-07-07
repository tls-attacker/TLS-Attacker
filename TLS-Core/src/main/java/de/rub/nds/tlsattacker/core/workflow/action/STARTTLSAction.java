package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement
public class STARTTLSAction extends ConnectionBoundAction {
    protected static final Logger LOGGER = LogManager.getLogger();

    public STARTTLSAction() {
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        LayerType topLevelType = state.getContext().getLayerStack().getHighestLayer().getLayerType();
        if(topLevelType != ImplementedLayers.SMTP) {
            throw new ActionExecutionException("STARTTLS is not defined for this protocol");
        }
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LayerStack layerStack = state.getContext().getLayerStack();
        int targetedLayerIndex = layerStack.getLayersInStack().indexOf(topLevelType);

        TlsContext tlsContext = state.getTlsContext();
        layerStack.insertLayer(new RecordLayer(tlsContext), targetedLayerIndex + 1);
        layerStack.insertLayer(new MessageLayer(tlsContext), targetedLayerIndex + 1);
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
