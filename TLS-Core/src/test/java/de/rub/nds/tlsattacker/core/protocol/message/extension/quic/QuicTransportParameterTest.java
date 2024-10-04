/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.quic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.quic.constants.QuicTransportParameterEntryTypes;
import java.util.List;
import org.junit.jupiter.api.Test;

public class QuicTransportParameterTest {

    @Test
    public void testQuicTransportParametersObjectToEntryListConversion() {
        QuicTransportParameters quicTransportParameters = new QuicTransportParameters();
        quicTransportParameters.setMaxIdleTimeout(60000L);
        quicTransportParameters.setMaxUdpPayloadSize(65527L);
        quicTransportParameters.setInitialMaxData(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataBidiLocal(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataBidiRemote(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataUni(2149983648L);
        quicTransportParameters.setInitialMaxStreamsBidi(2149983648L);
        quicTransportParameters.setInitialMaxStreamDataUni(2149983648L);
        quicTransportParameters.setAckDelayExponent(0L);
        quicTransportParameters.setMaxAckDelay(2000L);
        quicTransportParameters.setExtraEntries(
                List.of(
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.UNKNOWN,
                                new byte[] {34, 22, 44, 12})));

        List<QuicTransportParameterEntry> entryList = quicTransportParameters.toListOfEntries();

        assertEquals(quicTransportParameters, new QuicTransportParameters(entryList));
    }

    @Test
    public void testQuicTransportParametersEntryListToObjectConversion() {
        List<QuicTransportParameterEntry> quicTransportParameterList =
                List.of(
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.MAX_IDLE_TIMEOUT, 60000),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.MAX_UDP_PAYLOAD_SIZE, 65527),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.INITIAL_MAX_DATA, "802625a0"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                                "802625a0"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes
                                        .INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                                "802625a0"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.INITIAL_MAX_STREAM_DATA_UNI,
                                "802625a0"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.INITIAL_MAX_STREAMS_BIDI,
                                "80040000"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.INITIAL_MAX_STREAMS_UNI,
                                "80040000"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.ACK_DELAY_EXPONENT, "00"),
                        new QuicTransportParameterEntry(
                                QuicTransportParameterEntryTypes.MAX_ACK_DELAY, "19"));

        QuicTransportParameters quicTransportParameters =
                new QuicTransportParameters(quicTransportParameterList);

        assertEquals(quicTransportParameterList, quicTransportParameters.toListOfEntries());
    }
}
