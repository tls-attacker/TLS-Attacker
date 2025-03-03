package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.impl.HttpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.layer.impl.ToggleableLayerWrapper;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EnableLayerActionTest {
    private Config config;
    private State state;

    @BeforeEach
    public void setUp() {
        config = new Config();
        state = new State(config);
    }
    @Test
    public void testDisabledLayer() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext()), false),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.HTTP);
        assert !wrapper.isActive();
        action.execute(state);
        assert wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }
    @Test
    public void testAlreadyEnabledLayer() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext())),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.HTTP);
        assert wrapper.isActive();
        action.execute(state);
        assert wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }

    @Test
    public void testEnableLayerNotInStack() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext())),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);

        EnableLayerAction action = new EnableLayerAction(ImplementedLayers.SMTP);
        action.execute(state);
        Assertions.assertFalse(action.executedAsPlanned());
        assert action.isExecuted();
    }
}