/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class StarttlsTypeTest {

    /**
     * A bad sequence must also read as an error, or the trace would wait for a success reply that
     * is never coming instead of ending and letting the scanner retry with discovery. The mistake
     * has no symptom at runtime, so it is checked here.
     */
    @ParameterizedTest
    @EnumSource(StarttlsType.class)
    public void testBadSequenceRepliesAreAlsoErrors(StarttlsType type) {
        if (type.getBadSequenceRegex() == null) {
            return;
        }
        String badSequenceReply = SAMPLE_BAD_SEQUENCE_REPLIES.get(type);
        assertTrue(
                Pattern.compile(type.getBadSequenceRegex()).matcher(badSequenceReply).find(),
                type + " sample reply must match its own badSequenceRegex");
        assertTrue(
                Pattern.compile(type.getErrorRegex()).matcher(badSequenceReply).find(),
                type + " bad sequence must also match errorRegex, or the trace never aborts");
    }

    /** Every protocol that names a bad sequence must bring a reply to check it against. */
    @Test
    public void testEveryBadSequenceTypeHasASample() {
        for (StarttlsType type : StarttlsType.values()) {
            if (type.getBadSequenceRegex() != null) {
                assertTrue(
                        SAMPLE_BAD_SEQUENCE_REPLIES.containsKey(type),
                        "add a sample bad-sequence reply for " + type);
            }
        }
    }

    /**
     * A protocol either carries its whole upgrade wording or none of it, so that {@link
     * StarttlsType#hasDialect()} answers for every accessor rather than only for the greeting.
     */
    @ParameterizedTest
    @EnumSource(StarttlsType.class)
    public void testDialectWordingIsAllOrNothing(StarttlsType type) {
        for (String part :
                new String[] {
                    type.getGreetingRegex(),
                    type.getDiscoveryCommand(),
                    type.getDiscoveryReplyRegex(),
                    type.getUpgradeCommand(),
                    type.getUpgradeSuccessRegex(),
                    type.getErrorRegex()
                }) {
            assertTrue(
                    (part != null) == type.hasDialect(),
                    type + " must define either all of its upgrade wording or none of it");
        }
    }

    /** What each protocol actually says when it refuses for the order of the commands. */
    private static final Map<StarttlsType, String> SAMPLE_BAD_SEQUENCE_REPLIES =
            Map.of(StarttlsType.FTP, "503 Bad sequence of commands\r\n");
}
