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

public class ToggleLayerActionTest {
    private Config config;
    private State state;

    @BeforeEach
    public void setUp() {
        config = new Config();
        state = new State(config);
    }
    @Test
    public void testToggleDisabledLayer() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext()), false),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        ToggleLayerAction action = new ToggleLayerAction(ImplementedLayers.HTTP);
        assert !wrapper.isActive();
        action.execute(state);
        assert wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }
    @Test
    public void testToggleAlreadyEnabledLayer() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext())),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper != null;

        ToggleLayerAction action = new ToggleLayerAction(ImplementedLayers.HTTP);
        assert wrapper.isActive();
        action.execute(state);
        assert !wrapper.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();
    }

    @Test
    public void testToggleLayerNotInStack() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext())),
                new TcpLayer(state.getContext().getTcpContext())
        );
        state.getContext().setLayerStack(layerStack);

        ToggleLayerAction action = new ToggleLayerAction(ImplementedLayers.SMTP);
        action.execute(state);
        Assertions.assertFalse(action.executedAsPlanned());
        assert action.isExecuted();
    }

    @Test
    public void testToggleMultiple() {
        LayerStack layerStack = new LayerStack(
                state.getContext(),
                new ToggleableLayerWrapper<>(new HttpLayer(state.getContext().getHttpContext())),
                new ToggleableLayerWrapper<>(new TcpLayer(state.getContext().getTcpContext()), false)
        );
        state.getContext().setLayerStack(layerStack);
        ToggleableLayerWrapper wrapper1 = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(HttpLayer.class);
        assert wrapper1 != null;
        ToggleableLayerWrapper wrapper2 = (ToggleableLayerWrapper)state.getContext().getLayerStack().getLayer(TcpLayer.class);
        assert wrapper2 != null;

        ToggleLayerAction action = new ToggleLayerAction(ImplementedLayers.HTTP, ImplementedLayers.TCP);
        assert wrapper1.isActive();
        assert !wrapper2.isActive();
        action.execute(state);
        assert !wrapper1.isActive();
        assert wrapper2.isActive();
        assert action.executedAsPlanned();
        assert action.isExecuted();

    }
}