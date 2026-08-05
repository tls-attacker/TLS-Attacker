/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The one decision this enum carries: whether a reply that has not matched yet can already be
 * rejected. How replies of each shape are actually read is behaviour of {@link
 * ReceiveRegexTextAction} and is covered by its own test.
 */
public class TextReplyTerminationTest {

    /**
     * A single-line reply is fully determined by its first line, so a line that has diverged from
     * the expected pattern can never match and the upgrade is abandoned at once.
     */
    @Test
    public void testSingleLineFailsFastOnMismatch() {
        assertTrue(TextReplyTermination.SINGLE_LINE.failsFastOnMismatch());
    }

    /**
     * In a multiline reply the pattern targets a line further in, so the lines seen so far are
     * expected not to match and the reply must be read out before it can be judged.
     */
    @Test
    public void testMultiLineDoesNotFailFastOnMismatch() {
        assertFalse(TextReplyTermination.MULTI_LINE.failsFastOnMismatch());
    }
}
