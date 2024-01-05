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
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.util.ProviderUtil;
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
                    "802E0100020015000000100100800200800300800400800500800600400700C060B420BB3851D9D47ACB933DBE70399B868E0400000002066E0015000000031F3082031B30820203A00302010202140F1F2F34F5F6F7F8F9F0F0F9F8F7F6F5F4F3F2F1300D06092A864886F70D01010B0500305B3131302F0603550403132841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504061306476C6F62616C31153013060355040A130C544C532D41747461636B65723020180E3230323230313031303030303030180E323032343031303130303030303030323119301706035504031310746C732D61747461636B65722E636F6D31153013060355040A130C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001300D06092A864886F70D01010B050003820101004F1709E657D6C240C03269524A039B04C763DCCD6C7A397C5860B7B29E0F23FA7294FB22CC844736D99EF770A251AF17A780854ABC9BF6426882BF52E8E582AE15E8DE2E4ABBAC28FE02E0810A5A99F2B7E2A8FF3F8802F6D7EE99147BBE8034EC558C3D718191EF829299D5E8B0CF38C4635AF191B3E478819376878A9F5D95221ACDB09996B976B1196CA77F233AE0DA132CD931BA4A440B40DB2F2B6124CF60D69F936AC6507FA667C8382047A066D247651D0BC7B28AD1ED138A8EBBBF5FB36A01746DE775BBAA3D72A84C596503B29A2252CED5DEA8B710E589D7A8FAF2A512ACBC3B0F608FB53424825BB10F581CE4693419AADFA69656637B40EFB5F6000349308203453082022DA003020102021500DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF300D06092A864886F70D01010B0500305B3131302F0603550403132841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504061306476C6F62616C31153013060355040A130C544C532D41747461636B65723020180E3230323230313031303030303030180E3230323430313031303030303030305B3131302F0603550403132841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504061306476C6F62616C31153013060355040A130C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001300D06092A864886F70D01010B050003820101004A182FDD91EDF88FE2C2528005EFAC5AFFFA8633FFE771079DA0823CE53ECA07EB47BD5E5D5D310D8F5CBFAAA292286115A5C093489A71E74872E5561C233CADB291FE49D9E51EABE2C49092040D35A11F5E85C853D8F55FF5852B36BB944E57DEAFA37FCDC6303F15C469B3EC6A0AD22687D98B33EA28DDE19FF95D755619C3B569956E59CFD94FE56EF5A4F3D13CD4A67642BB147E17A580D95F6CFC56AB55510E9E72B69FC7B536D6FEC507C576978A68BF6B98A3170720B29C45478BC2CDFAA42AC23F79203E5E23850FE73AF80EB5C4E7B33DF1E4344BE05467457BB943E4C3B9701E74945F5201DDB1EE97E08DD03062A99E9F79C3B091B6EB0E103A540100800200800300800400800500800600400700C0");

    private ArrayList<byte[]> messageByteList = new ArrayList<>();

    public void setUp() throws IOException {
        config = new Config();
        config.setDefaultLayerConfiguration(StackConfiguration.SSL2);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);
        tlsContext = new Context(new State(config), new OutboundConnection()).getTlsContext();
        transportHandler = new FakeTransportHandler(null);
        tlsContext.setTransportHandler(transportHandler);
        ProviderUtil.addBouncyCastleProvider();
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
            System.out.println(
                    "SendByte: "
                            + ArrayConverter.bytesToHexString(
                                    transportHandler.getSendByte(), false, false));
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
