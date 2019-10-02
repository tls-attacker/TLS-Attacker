/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.ClientHelloPreparator;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.NoSuchPaddingException;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class RemBufferedChExtensionsActionTest {

    private State state;
    private TlsContext ctx;
    private WorkflowTrace trace;

    private ClientHelloMessage ch;
    private ClientHelloPreparator preparator;
    private RemBufferedChExtensionsAction action;
    private List<ExtensionType> remove;
    private List<ExtensionType> expected;
    private List<ExtensionType> actual;
    private byte[] expectedBytes;
    private int expectedLength;
    private int expectedMsgLength;
    private byte[] actualBytes;
    private int actualLength;
    private int actualMsgLength;

    public RemBufferedChExtensionsActionTest() {
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {

        expected = new ArrayList();
        expected.add(ExtensionType.EC_POINT_FORMATS);
        expected.add(ExtensionType.ELLIPTIC_CURVES);
        expected.add(ExtensionType.EXTENDED_MASTER_SECRET);
        expected.add(ExtensionType.ENCRYPT_THEN_MAC);
        expectedBytes = ArrayConverter.hexStringToByteArray("000B00020100000A000A000800130017001800190017000000160000");
        expectedLength = 28;

        Config config = Config.createConfig();
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddEncryptThenMacExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setAddSignatureAndHashAlgorithmsExtension(false);
        config.setDefaultClientNamedGroups(NamedGroup.SECP192R1, NamedGroup.SECP256R1, NamedGroup.SECP384R1,
                NamedGroup.SECP521R1);
        config.setDefaultServerNamedGroups(NamedGroup.SECP192R1, NamedGroup.SECP256R1, NamedGroup.SECP384R1,
                NamedGroup.SECP521R1);
        action = new RemBufferedChExtensionsAction();
        trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);
        ctx = state.getTlsContext();
        ch = new ClientHelloMessage(config);
        preparator = new ClientHelloPreparator(ctx.getChooser(), ch);
        preparator.prepare();
        expectedMsgLength = ch.getLength().getValue();
        ctx.getMessageBuffer().add(ch);
        remove = new ArrayList<>();
    }

    private List<ExtensionType> typesFromMessageList(List<ExtensionMessage> extMsgs) {
        List<ExtensionType> types = new ArrayList<>();
        for (ExtensionMessage msg : extMsgs) {
            types.add(msg.getExtensionTypeConstant());
        }
        return types;
    }

    private void compareList() {
        actual = typesFromMessageList(ch.getExtensions());
        assertThat("extension list should be adjusted", actual, equalTo(expected));
    }

    private void compareFields() {
        actualBytes = ch.getExtensionBytes().getValue();
        actualLength = ch.getExtensionsLength().getValue();
        actualMsgLength = ch.getLength().getValue();
        assertThat("bytes should be adjusted", actualBytes, equalTo(expectedBytes));
        assertThat("bytes lengths should be adjusted", actualLength, equalTo(expectedLength));
        assertThat("message lengths should be adjusted", actualMsgLength, equalTo(expectedMsgLength));
        assertTrue(action.isExecuted());
    }

    private void setExpectedFields(String extensionBytes) {
        expectedBytes = ArrayConverter.hexStringToByteArray(extensionBytes);
        int diff = expectedLength;
        expectedLength = extensionBytes.length() / 2;
        diff -= expectedLength;
        expectedMsgLength -= diff;
    }

    @Test
    public void removingNothingIsOk() {
        action.execute(state);
        actual = typesFromMessageList(ch.getExtensions());

        action.execute(state);

        assertTrue(action.isExecuted());
        compareList();
        compareFields();
    }

    @Test
    public void removingSingleExtensionIsOk() {
        expected.remove(ExtensionType.ELLIPTIC_CURVES);
        setExpectedFields("000B000201000017000000160000");

        action.setRemoveExtensions(ExtensionType.ELLIPTIC_CURVES);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareList();
        compareFields();
    }

    @Test
    public void removingMultipleExtensionsIsOk() {
        remove.add(ExtensionType.ENCRYPT_THEN_MAC);
        remove.add(ExtensionType.ELLIPTIC_CURVES);
        expected.removeAll(remove);
        setExpectedFields("000B0002010000170000");

        action.setRemoveExtensions(remove);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareList();
        compareFields();
    }

    @Test
    public void removingNonProposedExtensionsIsOk() {
        remove.add(ExtensionType.ALPN);
        remove.add(ExtensionType.RENEGOTIATION_INFO);
        remove.add(ExtensionType.ELLIPTIC_CURVES);
        expected.removeAll(remove);
        setExpectedFields("000B000201000017000000160000");

        action.setRemoveExtensions(remove);
        action.execute(state);

        assertTrue(action.isExecuted());
        compareList();
        compareFields();
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingEmptyActionYieldsMinimalOutput() {
        ActionTestUtils.marshalingEmptyActionYieldsMinimalOutput(RemBufferedChExtensionsAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshaclingEmptyObjectYieldsEqualObject() {
        ActionTestUtils.marshalingAndUnmarshalingEmptyObjectYieldsEqualObject(RemBufferedChExtensionsAction.class);
    }

    @Test
    @Category(SlowTests.class)
    public void marshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        action.setRemoveExtensions(ExtensionType.TOKEN_BINDING, ExtensionType.ALPN);
        ActionTestUtils.marshalingAndUnmarshalingFilledObjectYieldsEqualObject(action);
    }

}
