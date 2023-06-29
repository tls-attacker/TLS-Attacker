/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyEncapsulationMechanism;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;

public class EchConfigParserTest {

    private final Config config = new Config();

    @Test
    public void testDraft14() {

        byte[] recordBytes =
                ArrayConverter.hexStringToByteArray(
                        "0046FE0D0042B800200020AB31C5831D3BA3B6902FFA9CDC8CA22F318F74CFDB0795374910A28FAD9630540004000100010013636C6F7564666C6172652D65736E692E636F6D0000");
        EchConfigParser parser =
                new EchConfigParser(new ByteArrayInputStream(recordBytes), new TlsContext());
        List<EchConfig> echConfigs = new LinkedList<>();
        parser.parse(echConfigs);
        EchConfig echConfig = echConfigs.get(0);

        byte[] expectedEchConfigBytes =
                ArrayConverter.hexStringToByteArray(
                        "FE0D0042B800200020AB31C5831D3BA3B6902FFA9CDC8CA22F318F74CFDB0795374910A28FAD9630540004000100010013636C6F7564666C6172652D65736E692E636F6D0000");
        byte[] resultEchConfigBytes = echConfig.getEchConfigBytes();

        byte[] expectedVersion = EchVersion.DRAFT_14.getEchConfigVersion().getByteValue();
        byte[] resultVersion = echConfig.getConfigVersion().getByteValue();

        int expectedConfigId = 184;
        int resultConfigId = echConfig.getConfigId();

        HpkeKeyEncapsulationMechanism expectedKemId =
                HpkeKeyEncapsulationMechanism.DHKEM_X25519_HKDF_SHA256;
        HpkeKeyEncapsulationMechanism resultKemId = echConfig.getKem();

        byte[] expectedHpkePublicKey =
                ArrayConverter.hexStringToByteArray(
                        "AB31C5831D3BA3B6902FFA9CDC8CA22F318F74CFDB0795374910A28FAD963054");
        byte[] resultHpkePublicKey = echConfig.getHpkePublicKey();

        List<HpkeCipherSuite> expectedHpkeCipherSuites =
                List.of(
                        new HpkeCipherSuite(
                                HpkeKeyDerivationFunction.HKDF_SHA256,
                                HpkeAeadFunction.AES_128_GCM));
        List<HpkeCipherSuite> resultHpkeCipherSuites = echConfig.getHpkeCipherSuites();

        int expectedMaximumNameLength = 0;
        int resultMaximumNameLength = echConfig.getMaximumNameLength();

        byte[] expectedPublicName =
                ArrayConverter.hexStringToByteArray("636C6F7564666C6172652D65736E692E636F6D");
        byte[] resultPublicName = echConfig.getPublicDomainName();

        List<ExtensionMessage> expectedExtensionMessages = new LinkedList<>();
        List<ExtensionMessage> resultExtensionMessages = echConfig.getExtensions();

        assertArrayEquals(expectedEchConfigBytes, resultEchConfigBytes);
        assertArrayEquals(expectedVersion, resultVersion);
        assertEquals(expectedConfigId, resultConfigId);
        assertEquals(expectedKemId, resultKemId);
        assertArrayEquals(expectedHpkePublicKey, resultHpkePublicKey);
        assertEquals(expectedHpkeCipherSuites, resultHpkeCipherSuites);
        assertEquals(expectedMaximumNameLength, resultMaximumNameLength);
        assertArrayEquals(expectedPublicName, resultPublicName);
        assertEquals(expectedExtensionMessages, resultExtensionMessages);
    }
}
