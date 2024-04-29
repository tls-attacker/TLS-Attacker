package de.rub.nds.tlsattacker.core.layer.impl;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.stun.StunMessageClass;
import de.rub.nds.tlsattacker.core.constants.stun.StunMethodType;
import de.rub.nds.tlsattacker.core.layer.IgnoreLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;

public class StunTurnLayerTest {

    private StunTurnLayer layer;

    private IceContext iceContext;

    private Context context;

    public StunTurnLayerTest() {
    }

    @BeforeEach
    public void setUp() {
        State state = new State(new Config());
        context = state.getContext();
        LayerStack stack = new LayerStack(context, new StunTurnLayer(context.getIceContext()),
                new UdpLayer(context.getTlsContext()));
        
        context.setLayerStack(stack);
        iceContext = state.getContext().getIceContext();
        layer = (StunTurnLayer) state.getContext().getLayerStack().getLayerList().get(0);
        state.getContext().getLayerStack().getLayerList().get(1).setLayerConfiguration(new IgnoreLayerConfiguration<>(ImplementedLayers.UDP));
    }

    /**
     * Test of sendConfiguration method, of class StunTurnLayer.
     * @throws IOException 
     */
    @Test
    public void testSendConfiguration() throws IOException {
        layer.setLayerConfiguration(new SpecificSendLayerConfiguration<>(ImplementedLayers.STUN_TURN,
                new StunMessage(StunMessageClass.REQUEST, StunMethodType.CONNECT)));
        LayerProcessingResult<StunMessage> result = layer.sendConfiguration();
        System.out.println("" + ArrayConverter
                .bytesToHexString(result.getUsedContainers().get(0).getCompleteMessageBytes().getValue()));
    }
}
