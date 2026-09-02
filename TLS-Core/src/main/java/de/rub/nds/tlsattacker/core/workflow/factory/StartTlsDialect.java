/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

/**
 * The lines one text-based STARTTLS protocol exchanges to reach its TLS upgrade.
 *
 * <p>Every such protocol runs the same conversation and differs only in what it says, so the
 * wording lives here and the upgrade variants are built from it. The error pattern is part of that
 * wording: the numeric protocols report failures as a 4xx or 5xx status, while others use their own
 * vocabulary, so each one brings its own.
 *
 * @param greetingRegex matches the greeting the server sends on connect
 * @param discoveryCommand the capability discovery command, sent only by the discovery variant
 * @param discoveryReplyRegex matches the reply to the discovery command
 * @param upgradeCommand the command that asks for the TLS upgrade
 * @param upgradeSuccessRegex matches the reply that grants the upgrade
 * @param errorRegex matches the replies that refuse it
 */
record StartTlsDialect(
        String greetingRegex,
        String discoveryCommand,
        String discoveryReplyRegex,
        String upgradeCommand,
        String upgradeSuccessRegex,
        String errorRegex) {}
