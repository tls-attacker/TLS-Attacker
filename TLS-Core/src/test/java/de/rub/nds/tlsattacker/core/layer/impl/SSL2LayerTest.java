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
                    "802E0100020015000000100100800200800300800400800500800600400700C060B420BB3851D9D47ACB933DBE70399B868E0400000002066E00150000000349308203453082022DA003020102021500DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF300D06092A864886F70D01010B0500305B3131302F06035504030C2841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504060C06476C6F62616C31153013060355040A0C0C544C532D41747461636B65723020180E3230323230313031303030303030180E3230323430313031303030303030305B3131302F06035504030C2841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504060C06476C6F62616C31153013060355040A0C0C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001300D06092A864886F70D01010B050003820101004F00F6BBD0AC3F2A81A4D3EEEDD03BA4E0FBE710A9F87ECF8B904634B1776BDC19407ECD64AA42F8967559E245CCABA1603C448DA2A83592ECF9F71496F7A52312B0CAA76FFCBCE7ABBF9DC7608D4B3B83F57D275318861B70642C2AD142BC01AB7DD10BCC82A3CAFF1683C186BB01B95CA67B31B18ACD069AD18386146B55968F3DF3BC82654373857AB1404816DBA0E1300C8FE7FA0CA27396514FA844DD5CEF399873C657E8713D905C5010587D1A5CDB8285529E64DE54D0EB2CB2333EC76B68EA53EF2CEC77F1EE211BF7BCC18455A3E79EC12B29D4D873F5318E6C3ED2F53D6D57D55AE82B97330EC5F5CF5B5EDB797D0E73EA7B4EF26BE00DA2ADB15E00031F3082031B30820203A00302010202140F1F2F34F5F6F7F8F9F0F0F9F8F7F6F5F4F3F2F1300D06092A864886F70D01010B0500305B3131302F06035504030C2841747461636B6572204341202D20476C6F62616C20496E73656375726974792050726F7669646572310F300D06035504060C06476C6F62616C31153013060355040A0C0C544C532D41747461636B65723020180E3230323230313031303030303030180E323032343031303130303030303030323119301706035504030C10746C732D61747461636B65722E636F6D31153013060355040A0C0C544C532D41747461636B657230820122300D06092A864886F70D01010105000382010F003082010A0282010100C8820D6C3CE84C8430F6835ABFC7D7A912E1664F44578751F376501A8C68476C3072D919C5D39BD0DBE080E71DB83BD4AB2F2F9BDE3DFFB0080F510A5F6929C196551F2B3C369BE051054C877573195558FD282035934DC86EDAB8D4B1B7F555E5B2FEE7275384A756EF86CB86793B5D1333F0973203CB96966766E655CD2CCCAE1940E4494B8E9FB5279593B75AFD0B378243E51A88F6EB88DEF522A8CD5C6C082286A04269A2879760FCBA45005D7F2672DD228809D47274F0FE0EA5531C2BD95366C05BF69EDC0F3C3189866EDCA0C57ADCCA93250AE78D9EACA0393A95FF9952FC47FB7679DD3803E6A7A6FA771861E3D99E4B551A4084668B111B7EEF7D0203010001300D06092A864886F70D01010B0500038201010033CA043E79F10B38A19C4B2E03480B83C663D987471F34D6C34E4F0A519BAFFC0400259F76BF635398D489F13CD56B46BBFC2574E208E817C5FD80F6D76B068344F1FEA26B870D07233FBFB6090082B8690CC2E08D1BA919880995FECA887635AB3B4EF75B8DD55FBFF4D73BF4151664A87CCF2757B2AE5834816F2E02E23162D220146F893BCBAD7B85B0055F565387BDFAC38E6C9C0E242FC9A4C36BCE9CEAC650012EBA019B8AA0B6E33971363384063949619CF919741E671182C4658752A1E83DAB60565FB95F0CBF2D01E463FDCE7E049B31ACC0F56EDB4C575B4B4FD000AC1769494A2427299597F53A636CDF102A49C66E0A5CB9A07B0A8837F8394B0100800200800300800400800500800600400700C0");

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
