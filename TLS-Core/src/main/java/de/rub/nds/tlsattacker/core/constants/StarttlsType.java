/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsType {
    NONE,
    /**
     * server: "220-Welcome to FTP server\r\n220 Ready\r\n"<br>
     * client: "FEAT\r\n" (discovery variant only)<br>
     * server: "211-Features:\r\n AUTH TLS\r\n211 End\r\n"<br>
     * client: "AUTH TLS\r\n"<br>
     * server: "234 AUTH TLS\r\n"
     */
    FTP(
            "^220 ",
            "FEAT\r\n",
            "^211 ",
            "AUTH TLS\r\n",
            "^234 ",
            NumericStatus.ERROR_REGEX,
            NumericStatus.BAD_SEQUENCE_REGEX),
    IMAP,
    POP3,
    SMTP;

    /**
     * The reply patterns shared by the protocols that report failures as a numeric status.
     *
     * <p>They live in a nested class because an enum constructor argument cannot read a field of
     * its own enum.
     */
    private static final class NumericStatus {
        private static final String ERROR_REGEX = "^[45]\\d\\d ";

        private static final String BAD_SEQUENCE_REGEX = "^503 ";
    }

    private final String greetingRegex;
    private final String discoveryCommand;
    private final String discoveryReplyRegex;
    private final String upgradeCommand;
    private final String upgradeSuccessRegex;
    private final String errorRegex;
    private final String badSequenceRegex;
    private final boolean unpromptedPostHandshakeGreeting;

    StarttlsType() {
        this(null, null, null, null, null, null, null);
    }

    StarttlsType(
            String greetingRegex,
            String discoveryCommand,
            String discoveryReplyRegex,
            String upgradeCommand,
            String upgradeSuccessRegex,
            String errorRegex,
            String badSequenceRegex) {
        this(
                greetingRegex,
                discoveryCommand,
                discoveryReplyRegex,
                upgradeCommand,
                upgradeSuccessRegex,
                errorRegex,
                badSequenceRegex,
                false);
    }

    StarttlsType(
            String greetingRegex,
            String discoveryCommand,
            String discoveryReplyRegex,
            String upgradeCommand,
            String upgradeSuccessRegex,
            String errorRegex,
            String badSequenceRegex,
            boolean unpromptedPostHandshakeGreeting) {
        this.greetingRegex = greetingRegex;
        this.discoveryCommand = discoveryCommand;
        this.discoveryReplyRegex = discoveryReplyRegex;
        this.upgradeCommand = upgradeCommand;
        this.upgradeSuccessRegex = upgradeSuccessRegex;
        this.errorRegex = errorRegex;
        this.badSequenceRegex = badSequenceRegex;
        this.unpromptedPostHandshakeGreeting = unpromptedPostHandshakeGreeting;
    }

    /**
     * Whether this protocol's upgrade is built from the wording carried here.
     *
     * @return true if the accessors below describe an upgrade, false if the protocol is still built
     *     from its own message classes
     */
    public boolean hasDialect() {
        return greetingRegex != null;
    }

    /**
     * @return matches the greeting the server sends on connect
     */
    public String getGreetingRegex() {
        return greetingRegex;
    }

    /**
     * @return the capability discovery command, sent only by the discovery variant
     */
    public String getDiscoveryCommand() {
        return discoveryCommand;
    }

    /**
     * @return matches the reply to the discovery command
     */
    public String getDiscoveryReplyRegex() {
        return discoveryReplyRegex;
    }

    /**
     * @return the command that asks for the TLS upgrade
     */
    public String getUpgradeCommand() {
        return upgradeCommand;
    }

    /**
     * @return matches the reply that grants the upgrade
     */
    public String getUpgradeSuccessRegex() {
        return upgradeSuccessRegex;
    }

    /**
     * @return matches every reply that refuses the upgrade, so the trace stops instead of waiting
     *     for a success that will not come
     */
    public String getErrorRegex() {
        return errorRegex;
    }

    /**
     * Matches the refusals that only complain about the order of the commands, or null for a
     * protocol whose replies cannot say that much.
     *
     * <p>Must describe a subset of {@link #getErrorRegex()}: a bad sequence is still a refusal, and
     * one that the error pattern misses would leave the trace waiting rather than end it, so the
     * retry would never be reached.
     *
     * @return the bad-sequence pattern, or null
     */
    public String getBadSequenceRegex() {
        return badSequenceRegex;
    }

    /**
     * Whether the server sends an application-layer message of its own accord once the handshake
     * finishes, before the client has asked for anything. Protocols that re-advertise their
     * capabilities after the upgrade do this, ManageSieve among them (RFC 5804 section 2.2).
     *
     * @return true if a greeting arrives unprompted after the handshake
     */
    public boolean sendsUnpromptedPostHandshakeGreeting() {
        return unpromptedPostHandshakeGreeting;
    }
}
