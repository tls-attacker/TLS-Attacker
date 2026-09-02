/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.factory;

import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

/**
 * The lines one text-based STARTTLS protocol exchanges to reach its TLS upgrade.
 *
 * <p>Every such protocol runs the same conversation and differs only in what it says, so the
 * wording lives here and the upgrade variants are built from it. The error patterns are part of
 * that wording: the numeric protocols report failures as a 4xx or 5xx status, while others use
 * their own vocabulary, so each one brings its own.
 *
 * @param greetingRegex matches the greeting the server sends on connect
 * @param discoveryCommand the capability discovery command, sent only by the discovery variant
 * @param discoveryReplyRegex matches the reply to the discovery command
 * @param upgradeCommand the command that asks for the TLS upgrade
 * @param upgradeSuccessRegex matches the reply that grants the upgrade
 * @param errorRegex matches every reply that refuses the upgrade, so the trace stops instead of
 *     waiting for a success that will not come
 * @param badSequenceRegex matches the refusals that only complain about the order of the commands,
 *     or null for a protocol whose replies cannot say that much. Must describe a subset of {@code
 *     errorRegex}: a bad sequence is still a refusal, and one that {@code errorRegex} misses would
 *     leave the trace waiting rather than end it, so the retry would never be reached.
 */
public record StartTlsDialect(
        String greetingRegex,
        String discoveryCommand,
        String discoveryReplyRegex,
        String upgradeCommand,
        String upgradeSuccessRegex,
        String errorRegex,
        String badSequenceRegex) {

    /** Matches the error replies of the protocols that report failures as a numeric status. */
    private static final String NUMERIC_ERROR_STATUS_REGEX = "^[45]\\d\\d ";

    /**
     * The only refusal that says the upgrade could still succeed in a different order. RFC 959
     * defines 503 as a bad sequence of commands, which is exactly what a server means when it wants
     * its capability exchange run first. Every other error either rejects the command itself (500,
     * 502, 504), or describes a condition the exchange does not change (421, 431, 530), so retrying
     * those would only cost a connection.
     */
    private static final String NUMERIC_BAD_SEQUENCE_STATUS_REGEX = "^503 ";

    private static final StartTlsDialect FTP =
            new StartTlsDialect(
                    "^220 ",
                    "FEAT\r\n",
                    "^211 ",
                    "AUTH TLS\r\n",
                    "^234 ",
                    NUMERIC_ERROR_STATUS_REGEX,
                    NUMERIC_BAD_SEQUENCE_STATUS_REGEX);

    private static final Map<StarttlsType, StartTlsDialect> DIALECTS =
            new EnumMap<>(Map.of(StarttlsType.FTP, FTP));

    /**
     * The dialect of a STARTTLS protocol, if its upgrade is built from one.
     *
     * <p>The protocols that are still built from their own message classes have no dialect yet, so
     * callers must be able to do without one.
     *
     * @param type the STARTTLS type
     * @return the dialect, or empty if the protocol does not have one
     */
    public static Optional<StartTlsDialect> forType(StarttlsType type) {
        return Optional.ofNullable(DIALECTS.get(type));
    }
}
