/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.impl.MessageLayer;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.layer.impl.TcpLayer;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HeartbeatMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class WorkflowTraceTest {

    private WorkflowTrace trace;
    private Config config;
    private State state;
    private FakeTransportHandler fakeTransportHandler;

    @BeforeEach
    public void setUp() {
        config = new Config();
        trace = new WorkflowTrace();
        fakeTransportHandler = new FakeTransportHandler(null);
    }

    /** Test of makeGeneric method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testMakeGeneric() {}

    /** Test of strip method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testStrip() {}

    /** Test of reset method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testReset() {}

    /** Test of getDescription method, of class WorkflowTrace. */
    @Test
    public void testGetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /** Test of setDescription method, of class WorkflowTrace. */
    @Test
    public void testSetDescription() {
        trace.setDescription("testDesc");
        assertEquals("testDesc", trace.getDescription());
    }

    /** Test of add method, of class WorkflowTrace. */
    @Test
    public void testAdd_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(3));
    }

    /** Test of add method, of class WorkflowTrace. */
    @Test
    public void testAdd_int_TLSAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.addTlsAction(0, new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(0));
    }

    /** Test of remove method, of class WorkflowTrace. */
    @Test
    public void testRemove() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        assertEquals(3, trace.getTlsActions().size());
        trace.removeTlsAction(0);
        assertEquals(2, trace.getTlsActions().size());
    }

    /** Test of getTlsActions method, of class WorkflowTrace. */
    @Test
    public void testGetTLSActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(2, trace.getTlsActions().size());
        assertEquals(new SendAction(), trace.getTlsActions().get(0));
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(1));
    }

    /** Test of setTlsActions method, of class WorkflowTrace. */
    @Test
    public void testSetTlsActions() {
        LinkedList<TlsAction> actionList = new LinkedList<>();
        actionList.add(new SendAction());
        actionList.add(new ReceiveAction());
        trace.setTlsActions(actionList);
        assertEquals(2, trace.getTlsActions().size());
        assertEquals(new SendAction(), trace.getTlsActions().get(0));
        assertEquals(new ReceiveAction(), trace.getTlsActions().get(1));
    }

    /** Test of getMessageActions method, of class WorkflowTrace. */
    @Test
    public void testGetMessageActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(2, trace.getMessageActions().size());
        assertEquals(new SendAction(), trace.getMessageActions().get(0));
        assertEquals(new ReceiveAction(), trace.getMessageActions().get(1));
    }

    /** Test of getReceiveActions method, of class WorkflowTrace. */
    @Test
    public void testGetReceiveActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(1, trace.getReceivingActions().size());
        assertEquals(new ReceiveAction(), trace.getReceivingActions().get(0));
    }

    /** Test of getSendActions method, of class WorkflowTrace. */
    @Test
    public void testGetSendActions() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ChangeClientRandomAction());
        assertEquals(1, trace.getSendingActions().size());
        assertEquals(new SendAction(), trace.getSendingActions().get(0));
    }

    /** Test of getLastAction method, of class WorkflowTrace. */
    @Test
    public void testGetLastAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new ChangeCipherSuiteAction(), trace.getLastAction());
    }

    /** Test of getLastMessageAction method, of class WorkflowTrace. */
    @Test
    public void testGetLastMessageAction() {
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ReceiveAction());
        trace.addTlsAction(new SendAction());
        trace.addTlsAction(new ChangeCipherSuiteAction());
        assertEquals(new SendAction(), trace.getLastMessageAction());
        trace.addTlsAction(new ReceiveAction());
        assertEquals(new ReceiveAction(), trace.getLastMessageAction());
    }

    /** Test of executedAsPlanned method, of class WorkflowTrace. */
    @Test
    @Disabled("Not implemented")
    public void testConfiguredLooksLikeActual() {}

    /** Test of getName method, of class WorkflowTrace. */
    @Test
    public void testGetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    /** Test of setName method, of class WorkflowTrace. */
    @Test
    public void testSetName() {
        trace.setName("testName");
        assertEquals("testName", trace.getName());
    }

    @Test
    public void testGetFirstReceivedMessage() {
        SendAction sendClientHelloAction = new SendAction();
        sendClientHelloAction.setConfiguredMessages(List.of(new ClientHelloMessage()));

        SendAction sendHeartbeatAction = new SendAction();
        sendHeartbeatAction.setConfiguredMessages(List.of(new HeartbeatMessage()));

        AlertMessage alertMessage = new AlertMessage();
        ServerHelloMessage serverHelloMessage = new ServerHelloMessage();

        ReceiveAction receiveAlertMessageAction = new ReceiveAction();
        ReceiveAction receiveServerHelloAction = new ReceiveAction();

        receiveAlertMessageAction.setExpectedMessages(alertMessage);
        receiveServerHelloAction.setExpectedMessages(serverHelloMessage);

        trace.addTlsActions(
                sendClientHelloAction,
                receiveAlertMessageAction,
                sendHeartbeatAction,
                receiveServerHelloAction);

        state = new State(config, trace);

        state.getTlsContext().setTransportHandler(fakeTransportHandler);
        state.getContext()
                .setLayerStack(
                        new LayerStack(
                                state.getContext(),
                                new MessageLayer(state.getTlsContext()),
                                new RecordLayer(state.getTlsContext()),
                                new TcpLayer(state.getTcpContext())));

        state.getTlsContext().setTransportHandler(fakeTransportHandler);
        sendClientHelloAction.execute(state);
        fakeTransportHandler.setFetchableByte(ArrayConverter.hexStringToByteArray("150303020000"));
        receiveAlertMessageAction.execute(state);

        fakeTransportHandler.setFetchableByte(
                ArrayConverter.hexStringToByteArray(
                        "16030318dc020000660303651296844a26455f5839b4f3b14b90840fc5e9a5bfc9db7da7b590ccb3f01ac620ad4b0000e189bc8e48173b7df228d100f1e5d843ca23dc1bec7c1383ef6a4f85c03000001e000500000023000000100005000302683200170000ff01000100000000000b001004001001000a0430820a00308207e8a00302010202133300b39b8a93a61853b7e2d1e0000000b39b8a300d06092a864886f70d01010c05003059310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312a3028060355040313214d6963726f736f667420417a75726520544c532049737375696e67204341203032301e170d3233303632303232323135335a170d3234303631343232323135335a306a310b3009060355040613025553310b30090603550408130257413110300e060355040713075265646d6f6e64311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e311c301a060355040313136f6666696365617070732e6c6976652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100d429ca97ef5559b820bc3edf33e11cdc1cdc7c9ed8a1b00d3a8789edda487114bbb5336fbe25f57c46114617b734d6374c84af0d6fc30ef72cc6df05c15c849a91e87d0c165fa4f50d4b13fe301cb3a19ba0c840a95124408d048643d70defabdce563e8ca92e8e0130fb17dfeeda44f838857471a7bc7ba7d35e8e54041578b6380728428c516a5eac5d97a4dea410deff36369d9074ec53ca121df521d124bbacfbc3bfb0f4231c2809acb3f6118b7c25df3b7b285689add8ea22e223ff2ea5ea1c892d7f819bfdd74cba0c735057793a1c4d69eba369bb6ca9b3e2af9bd4b71a1f345b05f5e78177caa75f8bb527913010559342bcd0a5125d71fd9b0c7d50203010001a38205ae308205aa3082017c060a2b06010401d6790204020482016c048201680166007500eecdd064d5db1acec55cb79db4cd13a23287467cbcecdec351485946711fb59b00000188daef9e9b000004030046304402205f5083dfda31228c749957e112d0c63c66771025d65348fd6ba8c59ddd0345aa02202058710066535a14cf476249f7d56cd2c976bbfb6d7f5cd42d307562d007bdd900750048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d8847300000188daef9ea7000004030046304402206ace9e4dc8e945abf11514d69036c15a04749e5ca6d9e874d299ef95599d2ae702207a2f2a46f189924ec443c6eaa3cdf14cbb9016624628bebb921f1d685c3d51bd007600dab6bf6b3fb5b6229f9bc2bb5c6be87091716cbb51848534bda43d3048d7fbab00000188daef9ec50000040300473045022100bc0e31da76cdee18dc9108079e0389f49114dc6bc1b9ae880d0fd95768d097ec02205c28b4f8fd23a644f9795f02692a943bc37e2ff4de5aee5b31d4fa8db28acf01302706092b060104018237150a041a3018300a06082b06010505070302300a06082b06010505070301303c06092b0601040182371507042f302d06252b060104018237150887bdd71b81e7eb4682819d2e8ed00c87f0da1d5d8284e56982f3a73e0201640201263081ae06082b060105050701010481a130819e306d06082b060105050730028661687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63657274732f4d6963726f736f6674253230417a757265253230544c5325323049737375696e67253230434125323030322532302d253230787369676e2e637274302d06082b060105050730018621687474703a2f2f6f6e656f6373702e6d6963726f736f66742e636f6d2f6f637370301d0603551d0e0416041475ce75d24ba720185a70ffe5f43d533cabeff9a6300e0603551d0f0101ff0404030205a0308201c30603551d11048201ba308201b682136f6666696365617070732e6c6976652e636f6d82126f66666963657070652e6c6976652e636f6d82112a2e6f66666963652e6c6976652e636f6d820f6f66666963652e6c6976652e636f6d82152a2e6f6666696365617070732e6c6976652e636f6d82166f6666696365617070732d64662e6c6976652e636f6d82182a2e6f6666696365617070732d64662e6c6976652e636f6d82117777772e6f66666963657070652e636f6d82132a2e6f6e6c696e652e6f66666963652e636f6d82162a2e6f6e6c696e652e6f66666963653336352e636f6d82116f6e6c696e652e6f66666963652e636f6d82146f6e6c696e652e6f66666963653336352e636f6d82172a2e66702e6d6561737572652e6f66666963652e636f6d82182a2e74682e6f6666696365617070732e6c6976652e636f6d82192a2e7668732e6f6666696365617070732e6c6976652e636f6d821a2a2e766965772e6f6666696365617070732e6c6976652e636f6d82192a2e6f7074696e2e6f6e6c696e652e6f66666963652e636f6d821874722d6f66632d6166647761632e6f66666963652e636f6d821674722d6f66632d616664622e6f66666963652e636f6d300c0603551d130101ff0402300030640603551d1f045d305b3059a057a0558653687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f63726c2f4d6963726f736f6674253230417a757265253230544c5325323049737375696e67253230434125323030322e63726c30660603551d20045f305d3051060c2b0601040182374c837d01013041303f06082b060105050702011633687474703a2f2f7777772e6d6963726f736f66742e636f6d2f706b696f70732f446f63732f5265706f7369746f72792e68746d3008060667810c010202301f0603551d2304183016801400ab91fc216226979aa8791b61419060a96267fd301d0603551d250416301406082b0601050507030206082b06010505070301300d06092a864886f70d01010c05000382020100c07271b175f95971924979883a8cd4709e1558c6c457915889456b2c253d198787ac7eff34eca13c8bb79c7c54894fd9cbd13a9e503f3c29574efe49c6791e8304ee6545197c0d18409a271ae16748605944efc42f511018d2e28d1bf8ce2d28f52927e4c5ee355e0df632d9eba0bde667e2f2e8578d9326f983eeae22e73d9fedb545d8a22911c385d49fb49a0cc333cd469f279ae5e15be9695623957fbc739ed7f63301d81aa1f80a2643e9f499773e5ec0a0f7a6da9a9fb892e7da8a61d51ae869186df847ae05938705367012634b3777ed4396a6d5f6546ac02061fc8428fb85ad268c37b45595bdabc7359f2f32896b695bd0b6e52b780a271224392b861d8cfb4fddacf336835dffcf3fd63fa353235f1856a69ed19694fdf032ee1f4eddab7cec67d319e844d8135e1d74ec71f8153eaa5b09ac001b2bc023d2df2214d188b4ec125c7013ea43c2d283ba2f403c722849248fd72df7b318d1aaeaa6ebccdbbe51488d94daf26d3b0f4c6caed0a3f9cf58509783bb9bec915f9d8612cd4319b51836336bec79c511b2ee7ca9c21c59f3309ef1e5db7ef77a43c60f566f6dbc54aae490e22613bfdc652ad09fdcae026e22fcd5eb56f66de08d9149cfcabfeb16f9298ff5a2a85c2f23fbdb88b77c4846fc1966a116701b95b18c77fc645d15716e3ea5e633cc3c2e68a2e16bc9e08a1f2e4d8050fc0595e394472bd90005f7308205f3308204dba00302010202100c6ae97cced599838690a00a9ea53214300d06092a864886f70d01010c05003061310b300906035504061302555331153013060355040a130c446967694365727420496e6331193017060355040b13107777772e64696769636572742e636f6d3120301e06035504031317446967694365727420476c6f62616c20526f6f74204732301e170d3230303732393132333030305a170d3234303632373233353935395a3059310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312a3028060355040313214d6963726f736f667420417a75726520544c532049737375696e6720434120303230820222300d06092a864886f70d01010105000382020f003082020a0282020100e0623b52ba164e1f1c8eadde6264a60ee5c6879480bf2dcfdc2e236cf452063cbc5adadd5068ed0ce70b82b7b3d8ea296132210635d4b7b4d74f1b4986bf4cad1a8a83ba8ada468a28041bebc7fe2aad4173d2bba0fcd38ae2d0d159d5238ff48ce362e4222ba0169ed0aa3f858071900fb6936b34b3c12328aa9a24c34b8765160d5db2432e5694f8cf4329804326c509eb499eb5e6b050db9be755b04d8a0d38142b21d55dd2f2f7b91b3874f2822b2ff839c6af79a11ae011e38121e89e810a682ab2d8ca8dd1d53b78f07992242058439d90737e1183141d66c2d7314ad6b8bd492c064feb27a8e3bc924b12828e1ab9fc0516bd004fdcdfdc3ff889cca28ac36dea27f92456b1340d2543888897585d1cf5a6d21a1625f523e5f3a207708008cf07a527848aa47ad56e1d3fc386077458b941b740a7b3b92b17f105885039e1f28acd35ce4a589fa4aa5051af6caf1e67ccbd01c96df0f2147ed306eaae4185d9416640c35779fbd11957c18be59737d9fe757de25fa1629f862d6ee34a6a7164b1bf5c4cf8397b53b56c0b57e22420e7bf10317bf4a09acd6d925ce22f5489cfa22d4fa8de13b9d36fd06c81179b510bf6818d4aa9972d5861f78ac20455b3cdf3e64ba23a272674664a1fd4aa5396e72ac7bb225c9f64b83ac80c58c9335eec0f5a709dffa4698222427ff5d7cb5057388586f76322086069aa9b6ff70203010001a38201ad308201a9301d0603551d0e0416041400ab91fc216226979aa8791b61419060a96267fd301f0603551d230418301680144e2254201895e6e36ee60ffafab912ed06178f39300e0603551d0f0101ff040403020186301d0603551d250416301406082b0601050507030106082b0601050507030230120603551d130101ff040830060101ff020100307606082b06010505070101046a3068302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304006082b060105050730028634687474703a2f2f636163657274732e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7447322e637274307b0603551d1f047430723037a035a0338631687474703a2f2f63726c332e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7447322e63726c3037a035a0338631687474703a2f2f63726c342e64696769636572742e636f6d2f4469676943657274476c6f62616c526f6f7447322e63726c301d0603551d20041630143008060667810c0102013008060667810c010202301006092b06010401823715010403020100300d06092a864886f70d01010c0500038201010033a3f29d9963cf4da60b416ec9e43ab1122053f50c981947de65ded3475f37ec7e834a415afe618cd642f08b9cbd9a264a03d93a4fd3b04f1f027e572f6cd3b6524156d150a57441878b2c79e36d7e1e94713102118e58a078fb4eb51197c1a34e43bc9259f26146129c3ca7b63c6147408effde7f93de45d0fd22eeda593d42ce58812277561c415339d89f529528958f134ecce7992e5200aab805743e4b198fb102e272ba7bf5156cfba6963d67ca397186f36e7785989abe27b5b05ebfa7126caefc76923fddcafb3ff5893d826e2f412c3b73208d2dde0c25fb357a79ca5b9edd372941f454f012fec990b5c2a5fdf11e27770ed7e2a7c6684ed2945ec8160006f5010006f1308206ed0a0100a08206e6308206e206092b0601050507300101048206d3308206cf3081c5a2160414d323478374d492f1c5f8d5627ec21f3f42aba059180f32303233303931393033313435345a308199308196304c300906052b0e03021a0500041452feca108db4e5ab5268930d27c82ff215e24bb5041400ab91fc216226979aa8791b61419060a96267fd02133300b39b8a93a61853b7e2d1e0000000b39b8a8000180f32303233303931393032313431305aa011180f32303233303932373032333431305aa120301e301c06092b0601040182371504040f170d3233303932333032323431305a300d06092a864886f70d01010b05000382010100a6d503a51106be19b05935f3e8b3fd5d4f266ead1118e877feb40cbcbca56a5a58a19d7612b8bb451447a3e58156f53b2feddf6dfe43ae2d1c73ae833adf09bdbf9d03a2c165029f16aecdbf4d661d17d8ef28f3be2534aa88b3c9d14b58be90ad4099041e124d1878b024357e3030676f4d99f64775822386f842259292380a3ab6f555a1dc80ff70a951202517baceeff0930732a478f752ee49e0a895299a275498fc7402958ee57908471ddd23f7b64a106c0210d14c6f8b92118bad2f53a52138bd40d129ca834c2a8d043e0961d40efd9736d01c7850f80c814d1fcb2f2059261a8334c1b7bfd14fbcbf5fe363a5690fd2fc0c3523a199f1ffbd68b513a08204ef308204eb308204e7308202cfa00302010202133300ce5f2a3b2dc6e386b02787000000ce5f2a300d06092a864886f70d01010c05003059310b3009060355040613025553311e301c060355040a13154d6963726f736f667420436f72706f726174696f6e312a3028060355040313214d6963726f736f667420417a75726520544c532049737375696e67204341203032301e170d3233303931373135353030395a170d3233313031373135353030395a301e311c301a06035504031313417a75726543413032204f435350204365727430820122300d06092a864886f70d01010105000382010f003082010a0282010100b4e0de34d04c69a5f24c34d6b2386edc7962d539fa13af3e71c117a58771bbe82c1ee173abbd06dcf4b3fcb6da56a5a95798f6f2c6989d9a02cc19600c60246b349ab30a2507fb259e433cd51ae7a26e989997496e808397eff74400b374cd982c6e6d87ba199e749f9aed527ddbe433651255f7c777b1862f4d2205939e9c28922e434c898ed91ffa94b5eaa98d1dd819967d9bcbcccef0ce7fba290b51351c5768fb9ede0de2639fb61167261c612aff11002e069d1515a96e773a17dd50f78cb3c5cdada79e0e7e63788e531fc00247b01ce647b69d20423c6c51dfae6087171095bed0011bb8a11fdeddaae14de83d72ec170cfa68f23fa9292859c749230203010001a381e23081df300c0603551d130101ff0402300030130603551d25040c300a06082b06010505070309301d0603551d0e04160414d323478374d492f1c5f8d5627ec21f3f42aba059301f0603551d2304183016801400ab91fc216226979aa8791b61419060a96267fd300e0603551d0f0101ff040403020780303c06092b0601040182371507042f302d06252b060104018237150887bdd71b81e7eb4682819d2e8ed00c87f0da1d5d83d9d72281f4de1f020164020117301b06092b060104018237150a040e300c300a06082b06010505070309300f06092b060105050730010504020500300d06092a864886f70d01010c05000382020100a238eec7227a2e5f12e8a8ea30ef24aabc3849958f5e5cc1fc274803236d19a60de5c385fbc8af7186f179721c9385f82ddd676db53f247cbabaee9042df57a98599ba790ff8ee920026695e9011420f38cb452a220ebd9e1bb78017950e392b4133bd534a9a97aa083b27958c419d629c373eb8d4912c73f8d80c9c86eb67edf193a02007c2f6e81179a28149203e574b2cd960f6367024d95489bc461b0ad33f7c6f5404bc2f1b5fb7b57ee0a194f72d66569c14a6009479b7415d0144bd1fdeba965e65f9cbb46e09e9b210d9f806b57bdd90323bf133af98e510967ba4c933747c83acadeba1eab5aca64d66b8332c29b87768507676f5f936db3e9cb8fe4811ac144cd8a94d0ef8b7440a295bf42510c08024569c3e492c73a98ea22e43d890ec004f737ebc99c78fd2658d811981ffebfce58181eb782440ac352fc3b59cb23c33c8c919713cc7920edfc3e81d1343f888dd6dc80ff856160f05d2a9323a768c86214a4c21ab40b439ba33161fca576cd0b18433b7d3faffb934ad7c61504f2d948c99039ba240f95469e64ddeba9d919ab243530a515b23184d36ea814efeefd2f089eeecfe9312ee8054babdfc557edb8c0416e30303303beecc8a2fd3b612299c712e941febfa5def207b1ff2b9303da459393fd35dfe646ca429e7220116895d41d9a4ee22b73813403a3f453cd1c6eab12adabd108164280869480c0001690300186104299417ebb2c5f3bc0c766e5cc39a6a7371cfe88b6b78658d1e038b95aa6939da7e95e3a6e90d805f508cae20a6e55ace11e9c4fc7a60963803c443c8485c751eb06d71f0cc82dff9c31ca2ed70baa7c889e38e3c412d580192d2a4be3c7054f6080401004619423498293f5197c743fe320bd3e1f8b7e3e1360c956f8947062b4b493bdea7ea69c77551e014c94cff5e815110955d85b4de458295123e02ee38eaef66c381b1a67bd5485fc265f62e29bc096a926bc6a69e273cb7ee80ffb58c8955c2bfbb293eeff9a50cb8222528f1415765360167eb42a2b6ae33f4ba8af0fb1976b772dc55ac6b757c66bdd429607eb302fd39c8a561479834f705c3a5e0edc248d53e216d57b1f1c54904b37749c3b8859ba19960c52eabe80ee97114af39edbcb21ec5e2b3cd007018ad5100426db7816efda5666e6b549e82b7f531a928dfe008e92c5946937e532110d3fa7adc1136420b19e13e289f0fbc6ebc7274bcfd11400e000000"));
        receiveServerHelloAction.execute(state);

        assertEquals(alertMessage, trace.getFirstReceivedMessage(AlertMessage.class));
        assertEquals(serverHelloMessage, trace.getFirstReceivedMessage(ServerHelloMessage.class));
    }

    public void testGetFirstSendMessage() {
        ReceiveAction receiveAlertMessageAction = new ReceiveAction();
        receiveAlertMessageAction.setExpectedMessages(new AlertMessage());

        ReceiveAction receiveServerHelloAction = new ReceiveAction();
        receiveServerHelloAction.setExpectedMessages(new ServerHelloMessage());

        ClientHelloMessage clientHello = new ClientHelloMessage(config);
        HeartbeatMessage heartbeat = new HeartbeatMessage();

        SendAction sendClientHelloAction = new SendAction(clientHello);
        SendAction sendHeartbeatAction = new SendAction(heartbeat);

        trace.addTlsActions(
                sendClientHelloAction,
                receiveAlertMessageAction,
                sendHeartbeatAction,
                receiveServerHelloAction);
        state = new State(config, trace);

        state.getTlsContext().setTransportHandler(fakeTransportHandler);
        state.getContext()
                .setLayerStack(
                        new LayerStack(
                                state.getContext(),
                                new MessageLayer(state.getTlsContext()),
                                new TcpLayer(state.getTcpContext())));
        sendClientHelloAction.execute(state);
        sendHeartbeatAction.execute(state);

        assertEquals(clientHello, trace.getFirstSendMessage(ClientHelloMessage.class));
        assertEquals(heartbeat, trace.getFirstSendMessage(HeartbeatMessage.class));
    }
}
