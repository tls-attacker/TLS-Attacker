package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StopTLSActionTest {

    @Test
    public void testExecute() {
        Config config = new Config();
        // note this line is different from the StartTLS test
        config.setDefaultLayerConfiguration(StackConfiguration.SMTPS);
        State state = new State(config);
        StopTLSAction action = new StopTLSAction();
        assert state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.MESSAGE) ;
        assert state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.RECORD);
        action.execute(state);
        assert !state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.MESSAGE) ;
        assert !state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.RECORD);
    }

    @Test
    public void testRepeatedExecute() {
        // multiple "stops" are allowed, but do nothing
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTPS);
        State state = new State(config);
        StopTLSAction action = new StopTLSAction();
        action.execute(state);
        StopTLSAction action2 = new StopTLSAction();
        action2.execute(state);
        assert(action2.isExecuted());
    }

}