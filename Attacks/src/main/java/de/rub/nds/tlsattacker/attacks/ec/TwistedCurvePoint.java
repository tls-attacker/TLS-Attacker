/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 */
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
public enum TwistedCurvePoint {
    SECP160K1Twist(new BigInteger("CAA163F84C55E308840926EB7347951F5BBB937B", 16), new BigInteger(
            "804BC5BCB00D3C0A47571FFCC9275755F506680C", 16), new BigInteger("7"), NamedGroup.SECP160K1, new BigInteger(
            "C59136F5F837CEEE4C4071B911125BF127E89260", 16)),
    SECP160R1Twist(
            new BigInteger("3791A82ED128406D89E44E508CC98BCB60D09E67", 16),
            new BigInteger("B8F5B2AD14E4498F71BBDF7505E21A0C3257FB68", 16),
            new BigInteger("523"),
            NamedGroup.SECP160R1,
            new BigInteger("E708B3C59377C001AAA87F4743B64830AC27891B", 16)),
    SECP160R2Twist(new BigInteger("B1A722C8E8C916E4B63562C0429B36491187756", 16), new BigInteger(
            "E9DDA1D11EB136D574EAAFB70281E902E696F0", 16), new BigInteger("163"), NamedGroup.SECP160R2, new BigInteger(
            "3444EB0B52787F04B7807B26D57249F0FBBF597", 16)),
    SECP192K1Twist(
            new BigInteger("68EEA3E7F1C1504377C695B4F10F214CC71DB992366CFFAF", 16),
            new BigInteger("95DDFAAD265EC4B383C1F0679EE2EF94282FBA1570190F0B", 16),
            new BigInteger("373"),
            NamedGroup.SECP192K1,
            new BigInteger("884067DD2B6A474C4F8138A9C735B567C3F624FBB5A89253", 16)),
    SECP192R1Twist(
            new BigInteger("C62B835DE26E223FB2CEE974624C14C1320A462FCF75156", 16),
            new BigInteger("BD031D48BB024F6942BAED45F9B140637A708F59AEAE09E7", 16),
            new BigInteger("23"),
            NamedGroup.SECP192R1,
            new BigInteger("3DBF0D90776B937B86D57A65496AD0DD9F49D1D35CD489C9", 16)),
    SECP224K1Twist(
            new BigInteger("332C4168D13C82495CD5216012EAF9B2A6FF73EB80DBE470BAB28D32", 16),
            new BigInteger("21A117E36A4D8C047BAD31C5EDF8B4BF8308968DFFAF2425C33B5AE2", 16),
            new BigInteger("2161"),
            NamedGroup.SECP224K1,
            new BigInteger("73DDCEEA75D52BA94BB278BF4D339D40F467F6451EF26756A51E1F3", 16)),
    SECP224R1Twist(
            new BigInteger("CAE5F9CCFA939BA4DA1B171660E4E6225AFECBC54CB5A07670EF4FB7", 16),
            new BigInteger("AEB87151E7A3370301B7C984E52DFDB45AE6CF800143A50C4F2750EE", 16),
            new BigInteger("11"),
            NamedGroup.SECP224R1,
            new BigInteger("F517A55DD490FCD53A83392176BB9B1C6DD4E2F5EFDEE2F6454367BB", 16)),
    SECP256K1Twist(
            new BigInteger("4B11C45CC1BB2C2F82DB5D12C7814ABD58C342FCBDA0040E9303A3A65B6DBA66", 16),
            new BigInteger("8FFE225FAD43C14B63ABC2CD14A20EC87AC83CA3E1DFD7FAD1FB92F7BACFD544", 16),
            new BigInteger("13"),
            NamedGroup.SECP256K1,
            new BigInteger("7DC1351D8B1CB791B70411399271F823ED3AB9F54E52F591A5D4273D9F209570", 16)),
    SECP256R1Twist(
            new BigInteger("18F9BAE7747CD844E98525B7CCD0DAF6E1D20A818B2175A9A91E4EAE5343BC98", 16),
            new BigInteger("6212FB55CD57E1843CCBD1990DDA297E1C97DF1AED8B0DEE84F0EE33B5766859", 16),
            new BigInteger("5"),
            NamedGroup.SECP256R1,
            new BigInteger("B609C031AA531AA580CB2239D8DC7968F7F91391D780DBCBCF753FAF716E196E", 16)),
    // SECP384R1 twist is not feasible for large-scale scanning
    SECP521R1Twist(
            new BigInteger(
                    "108CBF3C9BF8E42135D87127556831076D84D5E549E645AFDA8A099249231B59B6C508DEE4E91C9A543E90EBC82613F86CB1290E29102A0F2FDEB57BF4193FB4639",
                    16),
            new BigInteger(
                    "53055C17CD6B3EBB59E1DA2D5AC97D04386D3B6F4520056FE748FEACBB599653A4F948E770392B6D679A8B83E28A70F7392C531BF3BFCE7E7007925AAEC4F53385",
                    16),
            new BigInteger("5"),
            NamedGroup.SECP521R1,
            new BigInteger(
                    "191E30E8841160C9FFC64D162A21DCA0B0620A8DB76AD93D2047BB3E2251379C447DFC7F4D715DBE3D04BB051013CA8F0AF79BB45B27BAAFC5AF287A54FE462C1EE",
                    16)),
    BRAINPOOLP256R1Twist(
            new BigInteger("A8944F96DE0FE0D82489CBC7E71F2F529CFCFEA03CA593D91462278731E19A5", 16),
            new BigInteger("17BDECE85FF8A6475A9B3D23867F8E0D1860E7F02B7BE21A02EA4E715E685B6", 16),
            new BigInteger("5"),
            NamedGroup.BRAINPOOLP256R1,
            new BigInteger("39248080291B8C5F9CE754E6045DA628B0B795AB3396C637844E48C4BC40FE54", 16)),
    BRAINPOOLP384R1Twist(
            new BigInteger(
                    "6CFE5AB49B37D0798AA4265B02F40E9060764FAF2B96E9475CD58FB0A6E8B6D16A1A540430076E0E67D9399AA29B0084",
                    16), new BigInteger(
                    "6B9BF25564CA942268D7EA63CCA04206FD7DD292C06538101F457E6CBB114B1FB151B249419234CDB026EB65BB1164C0",
                    16), new BigInteger("241"), NamedGroup.BRAINPOOLP384R1, new BigInteger(
                    "494C3442B50BD2543CBCE52C1C2210B8312667155D1E26262F45FFB85D216F2C6987B0D7DDB991156B4B3D473ECF81FA",
                    16)),
    BRAINPOOLP512R1Twist(
            new BigInteger(
                    "8A519BAFACCA8DAF51E22C6E9768534B5355C6806ADEE36E8F9A39D2DC4A3F3EF397C32EA6243A6E9676472EA5AF79C394BF08D62EDDAA8BD9ACCCAB8DBE50F3",
                    16),
            new BigInteger(
                    "9F9217ACB89B9A737DD14F7BA1F135610497CB8248BF35EC761F91C4071D76DED46F0D4A65D810FC4A8B174FB309764001C1BE8364810980C9433E3E6ECA826D",
                    16),
            new BigInteger("19"),
            NamedGroup.BRAINPOOLP512R1,
            new BigInteger(
                    "40B0D551038B96AD5557B4F4DBEA9CA80EDE1CAB267D90581D92EB7C40D1CA4F2C6C0543A283A87FD19BD7EA24E4908AD2B589589549F7015898DC99D6F43EDD",
                    16));

    private BigInteger publicPointBaseX;

    /**
     * An appropriate coordinate used to fill bytes when no compression is used
     * The attack does not require an Y-coordinate as we are targeting X-only
     * ladders
     */
    private BigInteger publicPointBaseY;

    /**
     * The value we are using to get a twisted curve d*y^2 = x^3 + ax + b
     */
    private BigInteger d;

    /**
     * The group the server actually meant to use
     */
    private NamedGroup intendedNamedGroup;
    private BigInteger order;

    private TwistedCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order,
            NamedGroup intendedNamedGroup, BigInteger d) {
        this.publicPointBaseX = publicPointBaseX;
        this.publicPointBaseY = publicPointBaseY;
        this.order = order;
        this.intendedNamedGroup = intendedNamedGroup;
        this.d = d;
    }

    /**
     * @return the d
     */
    public BigInteger getD() {
        return d;
    }

    /**
     * @param d
     *            the d to set
     */
    public void setD(BigInteger d) {
        this.d = d;
    }

    /**
     * @return the publicPointBaseX
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX
     *            the publicPointBaseX to set
     */
    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    /**
     * @return the publicPointBaseY
     */
    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    /**
     * @param publicPointBaseY
     *            the publicPointBaseY to set
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @return the intendedNamedGroup
     */
    public NamedGroup getIntendedNamedGroup() {
        return intendedNamedGroup;
    }

    /**
     * @param intendedNamedGroup
     *            the intendedNamedGroup to set
     */
    public void setIntendedNamedGroup(NamedGroup intendedNamedGroup) {
        this.intendedNamedGroup = intendedNamedGroup;
    }

    /**
     * @return the order
     */
    public BigInteger getOrder() {
        return order;
    }

    /**
     * @param order
     *            the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
    }

    public static TwistedCurvePoint fromIntendedNamedGroup(NamedGroup group) {
        for (TwistedCurvePoint point : values()) {
            if (point.getIntendedNamedGroup() == group) {
                return point;
            }
        }
        return null;
    }

    public static boolean isTwistVulnerable(NamedGroup group) {
        switch (group) {
            case SECP256K1:
            case SECP256R1:
            case SECP384R1:
            case SECP521R1:
            case BRAINPOOLP384R1:
            case BRAINPOOLP512R1:
                return false; // attack complexity > 2^100
            default:
                return true;
        }
    }
}
