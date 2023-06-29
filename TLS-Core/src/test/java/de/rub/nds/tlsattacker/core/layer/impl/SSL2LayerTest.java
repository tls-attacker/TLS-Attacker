/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import junit.framework.TestCase;

public class SSL2LayerTest extends TestCase {

    private Config config;

    private TlsContext tlsContext;

    private FakeTransportHandler transportHandler;

    private byte[] clientHello =
            ArrayConverter.hexStringToByteArray(
                    "802e0100020015000000100100800200800300800400800500800600400700c060b420bb3851d9d47acb933dbe70399b");
    private byte[] serverHello =
            ArrayConverter.hexStringToByteArray(
                    "802e0100020015000000100100800200800300800400800500800600400700c060b420bb3851d9d47acb933dbe70399b036304000000020343001500003082033f30820227a0030201020214581565240552edffc4c52ebb3a434b1cc18a7733300d06092a864886f70d01010b05003048310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03525542310c300a060355040b0c034e4453301e170d3231303631343133323132335a170d3234303430333133323132335a305c310b3009060355040613024445310c300a06035504080c034e5257310f300d06035504070c06426f6368756d310c300a060355040a0c03525542310c300a060355040b0c034e44533112301006035504030c096c6f63616c686f737430820122300d06092a864886f70d01010105000382010f003082010a0282010100ccb73b51ad7a40cc4ad79afab7211bbc7bee8cbbf0c598f7e28cd1394eecb06aa2d9f99cbc8d3757494694c0dc70d4418229223e06633164f5eca5616ab9d6858cb46883f9d6ddfc4f5a37fa8a3d23fad5b2554d7342eb9a644b03c36946c51c727fce66ee885114ff24c24a476307f05542b428c9b5651e6f060cb95297743650349f7178915a71bea4fe4bd18758b9b51a204f6083d9f6b8fae07591c5aeb0f01553a77c2d285ce2196f46e6604f73e9af79692da48dde5c5f31052c0b3c21b94d042e279a648bddb5f8d749b6f76a8c3af909111b1739b7ebf263e416e801dafa53ca19040e4a943a2978075ba59993a4a48419720b7d2a10fae909a67eb30203010001a30d300b30090603551d1304023000300d06092a864886f70d01010b05000382010100723e415aaaf16bcdc065d908cf4d02cd0b632b074882a352ac4843a91b57b8bef577596486d39a8489876114bde9a23866351193277d0bc65cc5a47e5efaa5be16e7ffd6c6344e9fe6c25bafccd95fc92c69ac4ca128533c73471bbd49cc60620e31655e5a678bed7c42454332934899925e3bd79919cd14556eef871afbc2a6933dc03dbb4a558d5b9584137069ca16ef42eb06dc812324110ad5280c106891375a856562607130cc474a3defab8545be8ce509910fa2b8056380747c4cb0297280df3e021bda61a01dac7f6b0959cb8a69e7674c5e7baa51bedca52180010955d2b31d072cd67e9d453da40a0dec8bf65ca1ddb6374e4f745077dd4f8f0eae0100800200800300800400800500800600400700c0");

    private ArrayList<byte[]> messageByteList = new ArrayList<>();

    public void setUp() throws IOException {
        config = new Config();
        config.setDefaultLayerConfiguration(LayerConfiguration.SSL2);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);

        tlsContext = new TlsContext(config);
        transportHandler = new FakeTransportHandler(null);
        tlsContext.setTransportHandler(transportHandler);

        messageByteList.add(clientHello);
        messageByteList.add(serverHello);
    }

    public void testSendConfiguration() throws IOException {
        ArrayList<SSL2Message> ssl2HandshakeMessages = new ArrayList<>();
        ssl2HandshakeMessages.add(new SSL2ClientHelloMessage());
        ssl2HandshakeMessages.add(new SSL2ServerHelloMessage());

        SpecificSendLayerConfiguration<SSL2Message> layerConfiguration;

        for (int i = 0; i < ssl2HandshakeMessages.size(); i++) {
            layerConfiguration =
                    new SpecificSendLayerConfiguration<>(
                            ImplementedLayers.SSL2, ssl2HandshakeMessages.get(i));
            tlsContext
                    .getLayerStack()
                    .getLayer(SSL2Layer.class)
                    .setLayerConfiguration(layerConfiguration);
            tlsContext.getLayerStack().getLayer(SSL2Layer.class).sendConfiguration();
            tlsContext.getLayerStack().getLayer(TcpLayer.class).sendConfiguration();
            assertEquals(
                    tlsContext
                            .getLayerStack()
                            .getLayer(SSL2Layer.class)
                            .getLayerResult()
                            .getUsedContainers()
                            .get(i),
                    ssl2HandshakeMessages.get(i));
            assertEquals(
                    Arrays.toString(transportHandler.getSendByte()),
                    Arrays.toString(messageByteList.get(i)));
        }
    }

    public void testSendData() {}

    public void testReceiveData() throws IOException {
        for (int i = 0; i < 2; i++) {
            transportHandler.setFetchableByte(messageByteList.get(i));
            tlsContext.getLayerStack().getLayer(SSL2Layer.class).receiveData();
            assertEquals(
                    tlsContext
                            .getLayerStack()
                            .getLayer(SSL2Layer.class)
                            .getLayerResult()
                            .getUsedContainers()
                            .get(0)
                            .getClass(),
                    SSL2ClientHelloMessage.class);
        }
    }

    public void testReceiveMoreDataForHint() {}
}
