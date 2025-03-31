package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.protocol.exception.ActionExecutionException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StartTLSActionTest {
    @Test
    public void testExecute() {
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);
        StartTLSAction action = new StartTLSAction();
        assert !state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.MESSAGE) ;
        assert !state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.RECORD);
        action.execute(state);
        assert state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.MESSAGE) ;
        assert state.getContext().getLayerStack().getLayersInStack().contains(ImplementedLayers.RECORD);
    }

    @Test
    public void testRepeatedExecute() {
        // multiple "starts" carry unclear semantics, so we disallow them
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);
        StartTLSAction action = new StartTLSAction();
        action.execute(state);
        StartTLSAction action2 = new StartTLSAction();
        assertFalse(action2.isExecuted());
    }

    @Test
    public void testPersistentContext() {
        // ensure that the TlsContext is preserved across multiple StartTLS/StopTLS cycles
        Config config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SMTP);
        State state = new State(config);

        StartTLSAction startAction = new StartTLSAction();
        startAction.execute(state);
        TlsContext originalTlsContext = state.getTlsContext();

        StopTLSAction stopAction = new StopTLSAction();
        stopAction.execute(state);

        startAction = new StartTLSAction();
        startAction.execute(state);
        TlsContext newTlsContext = state.getTlsContext();
        assert originalTlsContext == newTlsContext;
    }
}