package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.ProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerType;
import de.rub.nds.tlsattacker.core.layer.context.StarttlsContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This action toggles the MessageLayer and RecordLayer to the LayerStack to enable opportunistic TLS communication.
 * If the MessageLayer and RecordLayer are already present in the LayerStack, they will be removed.
 * Even though it does not transmit the actual application-specific STARTTLS command, it should only be used in protocols that support a form of STARTTLS command.
 * Currently, only SMTP is supported.
 */
@XmlRootElement
public class STARTTLSAction extends ConnectionBoundAction {
    protected static final Logger LOGGER = LogManager.getLogger();

    public STARTTLSAction() {
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        LayerType topLevelType = state.getContext().getLayerStack().getHighestLayer().getLayerType();
        if (topLevelType != ImplementedLayers.SMTP) {
            throw new ActionExecutionException("STARTTLS is not defined for this protocol");
        }
        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        LayerStack layerStack = state.getContext().getLayerStack();
        int targetedLayerIndex = layerStack.getLayersInStack().indexOf(topLevelType);

        TlsContext tlsContext = state.getTlsContext();
        StarttlsContext starttlsContext = state.getStarttlsContext();

        if (layerStack.getLayersInStack().contains(ImplementedLayers.MESSAGE) && layerStack.getLayersInStack().contains(ImplementedLayers.RECORD)) {
            ProtocolLayer oldRecordLayer = layerStack.removeLayer(RecordLayer.class);
            state.getStarttlsContext().setRecordLayer((RecordLayer) oldRecordLayer);
            ProtocolLayer oldMessageLayer = layerStack.removeLayer(MessageLayer.class);
            state.getStarttlsContext().setMessageLayer((MessageLayer) oldMessageLayer);
            setExecuted(true);
        } else if (!layerStack.getLayersInStack().contains(ImplementedLayers.MESSAGE) && !layerStack.getLayersInStack().contains(ImplementedLayers.RECORD)) {
            if(starttlsContext.getMessageLayer() == null) {
                starttlsContext.setMessageLayer(new MessageLayer(tlsContext));
            }
            if(starttlsContext.getRecordLayer() == null) {
                starttlsContext.setRecordLayer(new RecordLayer(tlsContext));
            }
            layerStack.insertLayer(starttlsContext.getRecordLayer(), targetedLayerIndex + 1);
            layerStack.insertLayer(starttlsContext.getMessageLayer(), targetedLayerIndex + 1);
            setExecuted(true);
        } else {
            // not sure why anyone would do this, but we do not meddle with such weird constructions where only one of the two exists
            throw new ActionExecutionException("Only one of the two TLS layers is present in the LayerStack - not suitable for STARTTLS toggle");
        }
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
