package de.rub.nds.tlsattacker.core.layer.impl;

import static org.junit.Assert.assertArrayEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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
import de.rub.nds.tlsattacker.core.layer.SpecificReceiveLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.stun.model.DataAttribute;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.stun.model.SoftwareAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import de.rub.nds.tlsattacker.core.stun.model.XorPeerAddressAttribute;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.stream.StreamTransportHandler;

public class StunTurnLayerTest {

    private StunTurnLayer layer;

    private IceContext iceContext;

    private Context context;

    public StunTurnLayerTest() {
    }

    @BeforeEach
    public void setUp() throws IOException {
        State state = new State(new Config());
        context = state.getContext();
        LayerStack stack = new LayerStack(context, new StunTurnLayer(context.getIceContext()),
                new UdpLayer(context.getTlsContext()));

        context.setLayerStack(stack);
        context.setTransportHandler(new StreamTransportHandler(0, ConnectionEndType.CLIENT,
                new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream()));
        context.getTransportHandler().initialize();
        iceContext = state.getContext().getIceContext();
        iceContext.getConfig().getIceConfig().setRandomizeStunTransactionIds(false);
        layer = (StunTurnLayer) state.getContext().getLayerStack().getLayerList().get(0);
        state.getContext().getLayerStack().getLayerList().get(1)
                .setLayerConfiguration(new IgnoreLayerConfiguration<>(ImplementedLayers.UDP));
    }

    /**
     * Test of sendConfiguration method, of class StunTurnLayer.
     * @throws IOException 
     */
    @Test
    public void testSendConfiguration() throws IOException {
        iceContext.getConfig().getIceConfig().setDefaultStunTransactionId(ArrayConverter.hexStringToByteArray("2112a442244fd6f80dbf5bd0db28fc55"));
        iceContext.getConfig().getIceConfig().setDefaultData(ArrayConverter.hexStringToByteArray("011100402112a442a637a7d7a0c6660a1dd4d560002000080001a8791550664e0009000f000004004261642052657175657374000008001436c457d17880317130bcd2aeaf1f0cce46b806c7802800049a643e4a"));
        iceContext.getConfig().getIceConfig().setDefaultAddress(ArrayConverter.hexStringToByteArray("3442C20C"));
        iceContext.getConfig().getIceConfig().setDefaultPort(25187);
        StunMessage message = new StunMessage(StunMessageClass.INDICATION, StunMethodType.DATA);
        message.getAttributeList().add(new DataAttribute());
        message.getAttributeList().add(new XorPeerAddressAttribute());
        message.getAttributeList().add(new SoftwareAttribute());
        message.getAttributeList().add(new FingerprintAttribute());
        layer.setLayerConfiguration(new SpecificSendLayerConfiguration<>(ImplementedLayers.STUN_TURN,
                message));
        LayerProcessingResult<StunMessage> result = layer.sendConfiguration();
        assertArrayEquals(ArrayConverter.hexStringToByteArray("001700842112a442244fd6f80dbf5bd0db28fc5500130054011100402112a442a637a7d7a0c6660a1dd4d560002000080001a8791550664e0009000f000004004261642052657175657374000008001436c457d17880317130bcd2aeaf1f0cce46b806c7802800049a643e4a00120008000143711550664e80220014436f7475726e2d342e362e312027476f7273742780280004642d00d6"), result.getUsedContainers().get(0).getCompleteMessageBytes().getValue());
    }

    @Test
    public void testReceiveConfiguration() throws IOException {
        layer.setLayerConfiguration(new SpecificReceiveLayerConfiguration<StunMessage>(ImplementedLayers.STUN_TURN, new StunMessage(null, null)));
        context.setTransportHandler(new StreamTransportHandler(0, ConnectionEndType.CLIENT,
                new ByteArrayInputStream(ArrayConverter.hexStringToByteArray("001700842112a442244fd6f80dbf5bd0db28fc5500130054011100402112a442a637a7d7a0c6660a1dd4d560002000080001a8791550664e0009000f000004004261642052657175657374000008001436c457d17880317130bcd2aeaf1f0cce46b806c7802800049a643e4a00120008000143711550664e80220014436f7475726e2d342e362e312027476f7273742780280004642d00d6")), new ByteArrayOutputStream()));
        context.getTransportHandler().initialize();
        layer.receiveMoreDataForHint(null);
        LayerProcessingResult<StunMessage> layerResult = layer.getLayerResult();
        StunMessage receivedMessage = layerResult.getUsedContainers().get(0);
        assertArrayEquals(ArrayConverter.hexStringToByteArray("001700842112a442244fd6f80dbf5bd0db28fc5500130054011100402112a442a637a7d7a0c6660a1dd4d560002000080001a8791550664e0009000f000004004261642052657175657374000008001436c457d17880317130bcd2aeaf1f0cce46b806c7802800049a643e4a00120008000143711550664e80220014436f7475726e2d342e362e312027476f7273742780280004642d00d6"), receivedMessage.getCompleteMessageBytes().getValue());
    
    }
    
}
