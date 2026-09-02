/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class StartTlsDialectTest {

    /**
     * A bad sequence must also read as an error, or the trace would wait for a success reply that
     * is never coming instead of ending and letting the scanner retry with discovery. The mistake
     * has no symptom at runtime, so it is checked here.
     */
    @ParameterizedTest
    @EnumSource(StarttlsType.class)
    public void testBadSequenceRepliesAreAlsoErrors(StarttlsType type) {
        StartTlsDialect dialect = StartTlsDialect.forType(type).orElse(null);
        if (dialect == null || dialect.badSequenceRegex() == null) {
            return;
        }
        String badSequenceReply = SAMPLE_BAD_SEQUENCE_REPLIES.get(type);
        assertTrue(
                Pattern.compile(dialect.badSequenceRegex()).matcher(badSequenceReply).find(),
                type + " sample reply must match its own badSequenceRegex");
        assertTrue(
                Pattern.compile(dialect.errorRegex()).matcher(badSequenceReply).find(),
                type + " bad sequence must also match errorRegex, or the trace never aborts");
    }

    /** Every dialect that names a bad sequence must bring a reply to check it against. */
    @Test
    public void testEveryBadSequenceDialectHasASample() {
        for (StarttlsType type : StarttlsType.values()) {
            StartTlsDialect dialect = StartTlsDialect.forType(type).orElse(null);
            if (dialect != null && dialect.badSequenceRegex() != null) {
                assertTrue(
                        SAMPLE_BAD_SEQUENCE_REPLIES.containsKey(type),
                        "add a sample bad-sequence reply for " + type);
            }
        }
    }

    /** What each protocol actually says when it refuses for the order of the commands. */
    private static final java.util.Map<StarttlsType, String> SAMPLE_BAD_SEQUENCE_REPLIES =
            java.util.Map.of(StarttlsType.FTP, "503 Bad sequence of commands\r\n");
}
