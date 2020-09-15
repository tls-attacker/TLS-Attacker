/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
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
            "C59136F5F837CEEE4C4071B911125BF127E89260", 16), new BigInteger("9C84267D3E6407C5964E752D0CE7A6B7DD9AE110",
            16), new BigInteger("E5A411F8B958C8CF70A312E4C01F2C0962F88290", 16), new BigInteger("13"), new BigInteger(
            "BF9082E7409B2DDAA99B8BC0618282890C4121AC", 16)),
    SECP160R1Twist(
            new BigInteger("3791A82ED128406D89E44E508CC98BCB60D09E67", 16),
            new BigInteger("B8F5B2AD14E4498F71BBDF7505E21A0C3257FB68", 16),
            new BigInteger("523"),
            NamedGroup.SECP160R1,
            new BigInteger("E708B3C59377C001AAA87F4743B64830AC27891B", 16),
            null,
            null,
            null,
            null),
    SECP160R2Twist(new BigInteger("B1A722C8E8C916E4B63562C0429B36491187756", 16), new BigInteger(
            "E9DDA1D11EB136D574EAAFB70281E902E696F0", 16), new BigInteger("163"), NamedGroup.SECP160R2, new BigInteger(
            "3444EB0B52787F04B7807B26D57249F0FBBF597", 16), new BigInteger("4E5E029E4E468289B5DA29B3EE8600697393C7A6",
            16), new BigInteger("BAD18050A6A226794C51AD943D15D3721F633CF8", 16), new BigInteger("457"), new BigInteger(
            "B5D70A87E90DB538403EB2953D4EECB202FE8361", 16)),
    SECP192K1Twist(
            new BigInteger("68EEA3E7F1C1504377C695B4F10F214CC71DB992366CFFAF", 16),
            new BigInteger("95DDFAAD265EC4B383C1F0679EE2EF94282FBA1570190F0B", 16),
            new BigInteger("373"),
            NamedGroup.SECP192K1,
            new BigInteger("884067DD2B6A474C4F8138A9C735B567C3F624FBB5A89253", 16),
            new BigInteger("90EA09CF46028698AD6D705CB550F505E2DB1F9E6533D07", 16),
            new BigInteger("8E98BD9BCA2CDEC91022FED09C66D8C38FD9460D3BE2ABE9", 16),
            new BigInteger("56383"),
            new BigInteger("9DAF16AF0679BAE9E4726AC603BBD98708CF0A088ED98975", 16)),
    SECP192R1Twist(
            new BigInteger("C62B835DE26E223FB2CEE974624C14C1320A462FCF75156", 16),
            new BigInteger("BD031D48BB024F6942BAED45F9B140637A708F59AEAE09E7", 16),
            new BigInteger("23"),
            NamedGroup.SECP192R1,
            new BigInteger("3DBF0D90776B937B86D57A65496AD0DD9F49D1D35CD489C9", 16),
            null,
            null,
            null,
            null),
    SECP224K1Twist(
            new BigInteger("332C4168D13C82495CD5216012EAF9B2A6FF73EB80DBE470BAB28D32", 16),
            new BigInteger("21A117E36A4D8C047BAD31C5EDF8B4BF8308968DFFAF2425C33B5AE2", 16),
            new BigInteger("2161"),
            NamedGroup.SECP224K1,
            new BigInteger("73DDCEEA75D52BA94BB278BF4D339D40F467F6451EF26756A51E1F3", 16),
            null,
            null,
            null,
            null),
    SECP224R1Twist(
            new BigInteger("CAE5F9CCFA939BA4DA1B171660E4E6225AFECBC54CB5A07670EF4FB7", 16),
            new BigInteger("AEB87151E7A3370301B7C984E52DFDB45AE6CF800143A50C4F2750EE", 16),
            new BigInteger("11"),
            NamedGroup.SECP224R1,
            new BigInteger("F517A55DD490FCD53A83392176BB9B1C6DD4E2F5EFDEE2F6454367BB", 16),
            new BigInteger("2D60A182BF5899ACA2029D9D7802FF7EBF649F613B5C25A2E9A95DED", 16),
            new BigInteger("900705C3013EA167CA394235736A35548221A9B513D4A5B18239810", 16),
            new BigInteger("47"),
            new BigInteger("DAA5F7E442CCC9D25D71DF9658DEF4454E9C0441CED7C0A6741754AA", 16)),
    SECP256K1Twist(
            new BigInteger("4B11C45CC1BB2C2F82DB5D12C7814ABD58C342FCBDA0040E9303A3A65B6DBA66", 16),
            new BigInteger("8FFE225FAD43C14B63ABC2CD14A20EC87AC83CA3E1DFD7FAD1FB92F7BACFD544", 16),
            new BigInteger("13"),
            NamedGroup.SECP256K1,
            new BigInteger("7DC1351D8B1CB791B70411399271F823ED3AB9F54E52F591A5D4273D9F209570", 16),
            new BigInteger("987BCDE3B17B59C4AB69517496E84BE739E8D3775B55B73EA5BDB24B557F7767", 16),
            new BigInteger("AB935FB858895479C8DA27F04CCAF1FE051CE50BEE2E25234C2392C6A5EBA876", 16),
            new BigInteger("3319"),
            new BigInteger("472E817D3C6B1F0A865FAFAD839760BBC9AAE80171D243A161797C7FD9061337", 16)),
    SECP256R1Twist(
            new BigInteger("18F9BAE7747CD844E98525B7CCD0DAF6E1D20A818B2175A9A91E4EAE5343BC98", 16),
            new BigInteger("6212FB55CD57E1843CCBD1990DDA297E1C97DF1AED8B0DEE84F0EE33B5766859", 16),
            new BigInteger("5"),
            NamedGroup.SECP256R1,
            new BigInteger("B609C031AA531AA580CB2239D8DC7968F7F91391D780DBCBCF753FAF716E196E", 16),
            new BigInteger("32238D77F2AC3D7FDFE418D5BB0855D3E303C80D0E9BBA9DA5040A7ED4EBAB3C", 16),
            new BigInteger("999D20A99AD3860FA6E72E5C8756709FEA0ABE398A2EEF7BF4941FAF576C96A3", 16),
            new BigInteger("13"),
            new BigInteger("D6904D6456EBE22335FDCC7B0E414E0417D5DEC00419BD0F02280855DF2ED671", 16)),
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
                    16),
            new BigInteger(
                    "47B9CF28E04B38796858545D60D6133FBDC20EDE086E5D95111C982B8C276628235E536C075637A97C0A6C30D02B83B19E578203473EEA16DFDEAECCB1DC0D9B19",
                    16),
            new BigInteger(
                    "93EF92BF8A66F492E0CD82071B8350299D541B82FF1A202DE9F974F0B720A5B4EC6EB84D2ACE0CD82BE837EC336957E18529E210A8F6E8704CC2F2F279CE93BA5F",
                    16),
            new BigInteger("7"),
            new BigInteger(
                    "17D3A076F32D076ACB269EDD813B1ADF86CD716FD9460C0A00DD8A0602F3AF4EF550AA6D91ECD2D5BCF41F6C17393D0EC4E9C9158FC9BD713E391FDFBB7C2C8D12F",
                    16)),
    BRAINPOOLP256R1Twist(
            new BigInteger("A8944F96DE0FE0D82489CBC7E71F2F529CFCFEA03CA593D91462278731E19A5", 16),
            new BigInteger("17BDECE85FF8A6475A9B3D23867F8E0D1860E7F02B7BE21A02EA4E715E685B6", 16),
            new BigInteger("5"),
            NamedGroup.BRAINPOOLP256R1,
            new BigInteger("39248080291B8C5F9CE754E6045DA628B0B795AB3396C637844E48C4BC40FE54", 16),
            new BigInteger("3CDF33BEFF2FD3EECC9BDD1B0B8B699E73AAC0F2B34C209E241B10A17515CB90", 16),
            new BigInteger("3E3920857D936F0571AD5E2A809C904FDA6B9AFDCE871D7A020074D7B14EA9D8", 16),
            new BigInteger("175939"),
            new BigInteger("8820D85C52D06395F8091EAD8773E891E1CF18990909DAF4949F6CA305BE4D9E", 16)),
    BRAINPOOLP384R1Twist(
            new BigInteger(
                    "6CFE5AB49B37D0798AA4265B02F40E9060764FAF2B96E9475CD58FB0A6E8B6D16A1A540430076E0E67D9399AA29B0084",
                    16), new BigInteger(
                    "6B9BF25564CA942268D7EA63CCA04206FD7DD292C06538101F457E6CBB114B1FB151B249419234CDB026EB65BB1164C0",
                    16), new BigInteger("241"), NamedGroup.BRAINPOOLP384R1, new BigInteger(
                    "494C3442B50BD2543CBCE52C1C2210B8312667155D1E26262F45FFB85D216F2C6987B0D7DDB991156B4B3D473ECF81FA",
                    16), new BigInteger(
                    "10362D53362BB7AB2008AC9997840ED4D39FBED87FDA799C1913448C5EA62651E33C929CFCE879895662B1F6C1D386",
                    16), new BigInteger(
                    "4C154117E789F768ADD650BBF179B07C7CE8153C2512A8BBBAF09CBEA63C01097298B4395368A4DA0950E8BD6F932D60",
                    16), new BigInteger("5557"), new BigInteger(
                    "6EA882743A226AE62B2CE3D537E668048F04EC087A2AE4B9A729539331281B15A4AA7A36DAC33E70ABB722541A1D6DA0",
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
                    16),
            new BigInteger(
                    "97BAD04F24F0EB201824955FC15F36E3BCF49C3726D5C89C6E4A917C4E3D657F9AF54F9909634812372CC1B5F48047C94066C1FF32CCACC33D4361314A4740FE",
                    16),
            new BigInteger(
                    "8F70C463B9826339789C24425AF5B2DFE20F6AFA14C5CF6A4838E6678E4AEF281A41F7F56B582E19039B2B3D41A3000F37E137D0891EB9DDA5B90EE4F8F5A809",
                    16),
            new BigInteger("41"),
            new BigInteger(
                    "D7B587C358E8E65D547BFDE5B27BE741B942EBD4467D2F8E586E90636920EB23EED57630583C3D9D1030858E0A1AADF12D3104CDE6A6E030DE90B035F1CBA08",
                    16)),
    // X-Curves use point of order 4 for evaluation of server behavior
    X25519Twist(
            new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 16),
            new BigInteger("5B8545C0F22DFADE38855A5CD1228352F134A9E655D637C03704BDE426506941", 16),
            new BigInteger("4"),
            NamedGroup.ECDH_X25519,
            new BigInteger("CA6648A697DC4F37B1BB5C5809E9F265332D9C6138371C0809B54D69C303AC7", 16),
            null,
            null,
            null,
            null),
    X448Twist(
            new BigInteger("1", 16),
            new BigInteger(
                    "9A6A7C05A0FA5E28F5804F2A40D7E9D4411FAA289AD9C54ACEFA9D5EAD8C5E1A0041CFBCA155921E66D4BDEC85414FFE42C18EFFEF918CB5",
                    16),
            new BigInteger("4"),
            NamedGroup.ECDH_X448,
            new BigInteger(
                    "F151DA48F37BACE95DEE7E0F6F2477C60C131264C2A5B900D214C76115C10CC86A22E33E6C07933F6369E8544580C6780F256EE77F8F3513",
                    16),
            null,
            null,
            null,
            null);
    private BigInteger publicPointBaseX;

    /**
     * An appropriate coordinate used to fill bytes when no compression is used
     * The attack does not require an Y-coordinate as we are targeting X-only
     * ladders To save computations, this coordinate is the y-coordinate of the
     * point obtained from the transformed twisted curve
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

    private BigInteger redundantBaseX;
    private BigInteger redundantBaseY;
    private BigInteger redundantOrder;
    private BigInteger redundantD;

    private TwistedCurvePoint(BigInteger publicPointBaseX, BigInteger publicPointBaseY, BigInteger order,
            NamedGroup intendedNamedGroup, BigInteger d, BigInteger redundantBaseX, BigInteger redundantBaseY,
            BigInteger redundantOrder, BigInteger redundantD) {
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
            case ECDH_X25519:
            case ECDH_X448:
                return false; // attack complexity > 2^100
            default:
                return true;
        }
    }

    public BigInteger getRedundantBaseX() {
        return redundantBaseX;
    }

    public void setRedundantBaseX(BigInteger redundantBaseX) {
        this.redundantBaseX = redundantBaseX;
    }

    public BigInteger getRedundantBaseY() {
        return redundantBaseY;
    }

    public void setRedundantBaseY(BigInteger redundantBaseY) {
        this.redundantBaseY = redundantBaseY;
    }

    public BigInteger getRedundantOrder() {
        return redundantOrder;
    }

    public void setRedundantOrder(BigInteger redundantOrder) {
        this.redundantOrder = redundantOrder;
    }

    public BigInteger getRedundantD() {
        return redundantD;
    }

    public void setRedundantD(BigInteger redundantD) {
        this.redundantD = redundantD;
    }
}
