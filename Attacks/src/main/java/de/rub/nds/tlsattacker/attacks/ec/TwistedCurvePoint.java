/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/*
 */

package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;

/**
 *
 */
@SuppressWarnings("SpellCheckingInspection")
public class TwistedCurvePoint {
    private BigInteger publicPointBaseX;

    /**
     * An appropriate coordinate used to fill bytes when no compression is used The attack does not require an
     * Y-coordinate as we are targeting X-only ladders To save computations, this coordinate is the y-coordinate of the
     * point obtained from the transformed twisted curve
     */
    private BigInteger publicPointBaseY;

    /**
     * The value we are using to get a twisted curve d*y^2 = x^3 + ax + b
     */
    private BigInteger pointD;

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
        this.pointD = d;
    }

    /**
     * Provides a Twisted Curve point with small order.
     * 
     * @param  group
     * @return       TwistedCurvePoint
     */
    public static TwistedCurvePoint smallOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new TwistedCurvePoint(new BigInteger("CAA163F84C55E308840926EB7347951F5BBB937B", 16),
                    new BigInteger("804BC5BCB00D3C0A47571FFCC9275755F506680C", 16), new BigInteger("7"),
                    NamedGroup.SECP160K1, new BigInteger("C59136F5F837CEEE4C4071B911125BF127E89260", 16));
            case SECP160R1:
                return new TwistedCurvePoint(new BigInteger("3791A82ED128406D89E44E508CC98BCB60D09E67", 16),
                    new BigInteger("B8F5B2AD14E4498F71BBDF7505E21A0C3257FB68", 16), new BigInteger("523"),
                    NamedGroup.SECP160R1, new BigInteger("E708B3C59377C001AAA87F4743B64830AC27891B", 16));
            case SECP160R2:
                return new TwistedCurvePoint(new BigInteger("B1A722C8E8C916E4B63562C0429B36491187756", 16),
                    new BigInteger("E9DDA1D11EB136D574EAAFB70281E902E696F0", 16), new BigInteger("163"),
                    NamedGroup.SECP160R2, new BigInteger("3444EB0B52787F04B7807B26D57249F0FBBF597", 16));
            case SECP192K1:
                return new TwistedCurvePoint(new BigInteger("68EEA3E7F1C1504377C695B4F10F214CC71DB992366CFFAF", 16),
                    new BigInteger("95DDFAAD265EC4B383C1F0679EE2EF94282FBA1570190F0B", 16), new BigInteger("373"),
                    NamedGroup.SECP192K1, new BigInteger("884067DD2B6A474C4F8138A9C735B567C3F624FBB5A89253", 16));
            case SECP192R1:
                return new TwistedCurvePoint(new BigInteger("C62B835DE26E223FB2CEE974624C14C1320A462FCF75156", 16),
                    new BigInteger("BD031D48BB024F6942BAED45F9B140637A708F59AEAE09E7", 16), new BigInteger("23"),
                    NamedGroup.SECP192R1, new BigInteger("3DBF0D90776B937B86D57A65496AD0DD9F49D1D35CD489C9", 16));
            case SECP224K1:
                return new TwistedCurvePoint(
                    new BigInteger("332C4168D13C82495CD5216012EAF9B2A6FF73EB80DBE470BAB28D32", 16),
                    new BigInteger("21A117E36A4D8C047BAD31C5EDF8B4BF8308968DFFAF2425C33B5AE2", 16),
                    new BigInteger("2161"), NamedGroup.SECP224K1,
                    new BigInteger("73DDCEEA75D52BA94BB278BF4D339D40F467F6451EF26756A51E1F3", 16));
            case SECP224R1:
                return new TwistedCurvePoint(
                    new BigInteger("CAE5F9CCFA939BA4DA1B171660E4E6225AFECBC54CB5A07670EF4FB7", 16),
                    new BigInteger("AEB87151E7A3370301B7C984E52DFDB45AE6CF800143A50C4F2750EE", 16),
                    new BigInteger("11"), NamedGroup.SECP224R1,
                    new BigInteger("F517A55DD490FCD53A83392176BB9B1C6DD4E2F5EFDEE2F6454367BB", 16));
            case SECP256K1:
                return new TwistedCurvePoint(
                    new BigInteger("4B11C45CC1BB2C2F82DB5D12C7814ABD58C342FCBDA0040E9303A3A65B6DBA66", 16),
                    new BigInteger("8FFE225FAD43C14B63ABC2CD14A20EC87AC83CA3E1DFD7FAD1FB92F7BACFD544", 16),
                    new BigInteger("13"), NamedGroup.SECP256K1,
                    new BigInteger("7DC1351D8B1CB791B70411399271F823ED3AB9F54E52F591A5D4273D9F209570", 16));
            case SECP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("18F9BAE7747CD844E98525B7CCD0DAF6E1D20A818B2175A9A91E4EAE5343BC98", 16),
                    new BigInteger("6212FB55CD57E1843CCBD1990DDA297E1C97DF1AED8B0DEE84F0EE33B5766859", 16),
                    new BigInteger("5"), NamedGroup.SECP256R1,
                    new BigInteger("B609C031AA531AA580CB2239D8DC7968F7F91391D780DBCBCF753FAF716E196E", 16));
            // case SECP384R1:
            case SECP521R1:
                return new TwistedCurvePoint(new BigInteger(
                    "108CBF3C9BF8E42135D87127556831076D84D5E549E645AFDA8A099249231B59B6C508DEE4E91C9A543E90EBC82613F86CB1290E29102A0F2FDEB57BF4193FB4639",
                    16),
                    new BigInteger(
                        "53055C17CD6B3EBB59E1DA2D5AC97D04386D3B6F4520056FE748FEACBB599653A4F948E770392B6D679A8B83E28A70F7392C531BF3BFCE7E7007925AAEC4F53385",
                        16),
                    new BigInteger("5"), NamedGroup.SECP521R1,
                    new BigInteger(
                        "191E30E8841160C9FFC64D162A21DCA0B0620A8DB76AD93D2047BB3E2251379C447DFC7F4D715DBE3D04BB051013CA8F0AF79BB45B27BAAFC5AF287A54FE462C1EE",
                        16));
            case BRAINPOOLP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("A8944F96DE0FE0D82489CBC7E71F2F529CFCFEA03CA593D91462278731E19A5", 16),
                    new BigInteger("17BDECE85FF8A6475A9B3D23867F8E0D1860E7F02B7BE21A02EA4E715E685B6", 16),
                    new BigInteger("5"), NamedGroup.BRAINPOOLP256R1,
                    new BigInteger("39248080291B8C5F9CE754E6045DA628B0B795AB3396C637844E48C4BC40FE54", 16));
            case BRAINPOOLP384R1:
                return new TwistedCurvePoint(new BigInteger(
                    "6CFE5AB49B37D0798AA4265B02F40E9060764FAF2B96E9475CD58FB0A6E8B6D16A1A540430076E0E67D9399AA29B0084",
                    16),
                    new BigInteger(
                        "6B9BF25564CA942268D7EA63CCA04206FD7DD292C06538101F457E6CBB114B1FB151B249419234CDB026EB65BB1164C0",
                        16),
                    new BigInteger("241"), NamedGroup.BRAINPOOLP384R1,
                    new BigInteger(
                        "494C3442B50BD2543CBCE52C1C2210B8312667155D1E26262F45FFB85D216F2C6987B0D7DDB991156B4B3D473ECF81FA",
                        16));
            case BRAINPOOLP512R1:
                return new TwistedCurvePoint(new BigInteger(
                    "8A519BAFACCA8DAF51E22C6E9768534B5355C6806ADEE36E8F9A39D2DC4A3F3EF397C32EA6243A6E9676472EA5AF79C394BF08D62EDDAA8BD9ACCCAB8DBE50F3",
                    16),
                    new BigInteger(
                        "9F9217ACB89B9A737DD14F7BA1F135610497CB8248BF35EC761F91C4071D76DED46F0D4A65D810FC4A8B174FB309764001C1BE8364810980C9433E3E6ECA826D",
                        16),
                    new BigInteger("19"), NamedGroup.BRAINPOOLP512R1,
                    new BigInteger(
                        "40B0D551038B96AD5557B4F4DBEA9CA80EDE1CAB267D90581D92EB7C40D1CA4F2C6C0543A283A87FD19BD7EA24E4908AD2B589589549F7015898DC99D6F43EDD",
                        16));
            case ECDH_X25519:
                return new TwistedCurvePoint(
                    new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 16),
                    new BigInteger("5B8545C0F22DFADE38855A5CD1228352F134A9E655D637C03704BDE426506941", 16),
                    new BigInteger("4"), NamedGroup.ECDH_X25519,
                    new BigInteger("CA6648A697DC4F37B1BB5C5809E9F265332D9C6138371C0809B54D69C303AC7", 16));
            case ECDH_X448:
                return new TwistedCurvePoint(new BigInteger("1", 16), new BigInteger(
                    "9A6A7C05A0FA5E28F5804F2A40D7E9D4411FAA289AD9C54ACEFA9D5EAD8C5E1A0041CFBCA155921E66D4BDEC85414FFE42C18EFFEF918CB5",
                    16), new BigInteger("4"), NamedGroup.ECDH_X448,
                    new BigInteger(
                        "F151DA48F37BACE95DEE7E0F6F2477C60C131264C2A5B900D214C76115C10CC86A22E33E6C07933F6369E8544580C6780F256EE77F8F3513",
                        16));
            default:
                return null;
        }
    }

    /**
     * Provides a Twisted Curve point with an order that is greater than the order of the point returned by
     * smallOrder(group).
     * 
     * @param  group
     * @return       TwistedCurvePoint
     */
    public static TwistedCurvePoint alternativeOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new TwistedCurvePoint(new BigInteger("9C84267D3E6407C5964E752D0CE7A6B7DD9AE110", 16),
                    new BigInteger("4D169E9BB555AC7F719591EC0A90164C6401206A", 16), new BigInteger("13"),
                    NamedGroup.SECP160K1, new BigInteger("9E8D3199FD3570027A6E1D0850E06EBFCE756F86", 16));
            case SECP160R1:
                return new TwistedCurvePoint(new BigInteger("F4184DA39ACF4D188776C4F158E7F89FB4CA9855", 16),
                    new BigInteger("3E2C39B04BDD5B2ED6EF918B047A8BA19CEBD391", 16), new BigInteger("11855018473"),
                    NamedGroup.SECP160R1, new BigInteger("ED06DE9D4832262BE18A969994749C75E5BD5039", 16));
            case SECP160R2:
                return new TwistedCurvePoint(new BigInteger("D3A76A4198988A7A2B57CDD078A3516DEEA62E84", 16),
                    new BigInteger("D580D394BC089E85195952EC88898BCFF3A1F5BC", 16), new BigInteger("457"),
                    NamedGroup.SECP160R2, new BigInteger("ADA194B09D98F37CD19AB395364AD759E9308FC1", 16));
            case SECP192K1:
                return new TwistedCurvePoint(new BigInteger("7AB9A222542FAC7568B77F46C380D406208FDC8307E1136C", 16),
                    new BigInteger("E327060D092CB38C607B2138EE3965D5462DEA1C1DCD413E", 16), new BigInteger("56383"),
                    NamedGroup.SECP192K1, new BigInteger("6EE349745C5A6698FCA8C84071DEF196C9C0E63CB841E10C", 16));
            case SECP192R1:
                return new TwistedCurvePoint(new BigInteger("F4DBC8267E3397902590C080EAD3505F71C5EF26E77139FE", 16),
                    new BigInteger("E60132AA3824F2F2EE02DBB82B9902BB0B7161209376CA14", 16),
                    new BigInteger("10864375060560251605900677743"), NamedGroup.SECP192R1,
                    new BigInteger("BD20F6E0768CC832AC7D64308876260BC4E8D50E7F0B39CA", 16));
            case SECP224K1:
                return new TwistedCurvePoint(
                    new BigInteger("B5472F4F7846F6B6ADA8D07FE95B277DC68B413AFBE2B4336D62424D", 16),
                    new BigInteger("4FDEBFC2CDC9EB2B7C7861D0D84A2923C6A659C46CA8EF2EA64C3844", 16),
                    new BigInteger("74128698849747076047230957053"), NamedGroup.SECP224K1,
                    new BigInteger("6A77E4ED900DEBDD68B6417C9B9CE9DD29492554E8B3A13A32DDE1EF", 16));
            case SECP224R1:
                return new TwistedCurvePoint(
                    new BigInteger("AA145DD90EB7F9A69B90F371BD20FD5CCCE1F476E1226BFD836F74E5", 16),
                    new BigInteger("784131970975B6464221AC6E020419918416BE2B4E9D99A740258E9D", 16),
                    new BigInteger("47"), NamedGroup.SECP224R1,
                    new BigInteger("180952C95466BA54FED99E93AD1AC36CB45C9AF3DB6AB54910556022", 16));
            case SECP256K1:
                return new TwistedCurvePoint(
                    new BigInteger("55BC3A2DF867DF94946938FE89EF88412E375895FC37E3A10583EDFCE02BBA68", 16),
                    new BigInteger("8E8218F976D61730B6AB7C1926875C7CEA6B60A4FDAD0A10F021B52D99C51C2D", 16),
                    new BigInteger("3319"), NamedGroup.SECP256K1,
                    new BigInteger("41E67D8ACDC8D180263A66C7CCE6D99AD57A2F484D8CE49663EFADEC15EB7179", 16));
            case SECP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("C8919F855F87325D8357A5AECD199F2D293A4E3DA6EFB08B06FC4DF50A287489", 16),
                    new BigInteger("46E408F396BB2381C8B8CD19857BC52ADEDE93E523C25855666C1E820DEB7BAD", 16),
                    new BigInteger("13"), NamedGroup.SECP256R1,
                    new BigInteger("2803473FA06D6328C641EFFB5BF6467F10B12682750184F105FC9858033AD62F", 16));
            // case SECP384R1:
            case SECP521R1:
                return new TwistedCurvePoint(new BigInteger(
                    "9CC73141CF1843D2B2C95DC5CBC4D615C6DA4814C1C7208615D8E78C7A8666ABA1852FAAA45A45D32BD0FDE6EA78F262A96BF1E02949CEA48C33C695103683048",
                    16),
                    new BigInteger(
                        "1EB73198D4E09CBBFB906B97EC878F5C4BA5A9569E87FF1D3D50D181FC828F0C67824EEC5C216DBA75FC37583EDC5E75971BD7E6206CA58DC3DF2256F5941BB4C84",
                        16),
                    new BigInteger("7"), NamedGroup.SECP521R1,
                    new BigInteger(
                        "8810FB26DC36BF7385485F8D129F7F7A1661455F92354A45438DE2B4BA08D95E3621852DB0E483E4FEA999DB9C27C309BF3A96E6BA4820E1B7B34F1DFF8965C6AA",
                        16));
            case BRAINPOOLP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("8643A0E19EF6464FBB8E413E15BCBD01DD18C98AAA58E1EF99F99D2345311B67", 16),
                    new BigInteger("A7222E3B35D69F71EE5E9F036E3339D3A4124D0CD0E4E63DD6B89969E6A3A4F9", 16),
                    new BigInteger("175939"), NamedGroup.BRAINPOOLP256R1,
                    new BigInteger("4773FB4A1F84DA9B330E4992FA1198A05AB82CA45C4755DC25D1F7B6B7957A", 16));
            case BRAINPOOLP384R1:
                return new TwistedCurvePoint(new BigInteger(
                    "3FEB2F8902206DE9BE1350BABE014D492BCE4B803B6EA18799819A784FCE766A86D00648BF3920F1C49EA18B76F93D8C",
                    16),
                    new BigInteger(
                        "554975C2AC6EC495E9F7482053736EC1C922C3CFDA088E0B21BDBAAC55DA9AAA3E345EE33C63FE248D1F105311063320",
                        16),
                    new BigInteger("5557"), NamedGroup.BRAINPOOLP384R1,
                    new BigInteger(
                        "4F5A014EE3B0DC4EBE349B6F04D71B28D27C731EBD1889486E7731E5153DC98141B855B86E528C0253B3943E134CC75D",
                        16));
            case BRAINPOOLP512R1:
                return new TwistedCurvePoint(new BigInteger(
                    "5D9F8E359B4BD2F4E88CFF1C658B1EDAEE73B7A16DB0A597F9818E22D599E81EBF376507BD8BC62047717550EE552237488E02B32B4E983F2E7B0DD05B7AE7D2",
                    16),
                    new BigInteger(
                        "1F58CC279992581A5C4C167405F2FAA69717CAE1A8BB3F974B4F4A9DCEF76C122AD4F60C3F17A944463FC02FCBA7B5C08DCE5257AE1CE9CBD3CA37C9BE1013E6",
                        16),
                    new BigInteger("41"), NamedGroup.BRAINPOOLP512R1,
                    new BigInteger(
                        "31F43260694E4C39A125AE2757506FEF5CD49766C8C6603DE017C94AE2F923034F90F6FA6D1D9A29C181999E9B2FCAB54CFFC46CD14D27E48316F3C429BA060B",
                        16));
            default:
                return null;
        }
    }

    /**
     * Provides a Twisted Curve point with an order that is far greater than the order of the point returned by
     * smallOrder(group) and alternativeOrder(group).
     * 
     * @param  group
     * @return       TwistedCurvePoint
     */
    public static TwistedCurvePoint largeOrder(NamedGroup group) {
        switch (group) {
            case SECP160K1:
                return new TwistedCurvePoint(new BigInteger("5FCCCA5A8159FC7F96160B0A6A18C763FDAAA6F4", 16),
                    new BigInteger("17F6FB729D1BB98DBCC99E477B3A346D04C15566", 16), new BigInteger("153607"),
                    NamedGroup.SECP160K1, new BigInteger("860B7D478DDEE3FD227A1DE4354BACE63135D75D", 16));
            case SECP160R1:
                return new TwistedCurvePoint(new BigInteger("19C789A1587E2220B009EA258CA14B10DA4AC2EF", 16),
                    new BigInteger("6C2A6FDD88D6E8CA81DA80BED98BDD2A624C084B", 16),
                    new BigInteger("235719430040354028377973833190775523"), NamedGroup.SECP160R1,
                    new BigInteger("11939C1A0932877A46167E64D5BD655C0CE5CB0D", 16));
            case SECP160R2:
                return new TwistedCurvePoint(new BigInteger("44DBA585B7AB04AD0FC223A7C96A2A6074E7427F", 16),
                    new BigInteger("9F5F7CF0A17BD1E77B673130963D0DE667D74F0D", 16),
                    new BigInteger("11899113760119541370164111066275852599"), NamedGroup.SECP160R2,
                    new BigInteger("4D610505F8BE3D6E47AB2F7B5D0BB2FE342CBE16", 16));
            case SECP192K1:
                return new TwistedCurvePoint(new BigInteger("BE403BE1E072BD43284DD8E6FA0ED4E71D1D7D66D8EEE872", 16),
                    new BigInteger("8E48191C5BB1B183B7F368D5BE2DF06C5AF78E6901A60545", 16), new BigInteger("619124299"),
                    NamedGroup.SECP192K1, new BigInteger("463973CB009D48867D731EF7DE5AD982A80BE4D7CD4C2F85", 16));
            case SECP192R1:
                return new TwistedCurvePoint(new BigInteger("23D188A0920E8F8F08506CD694681CD00A241F12DE790C68", 16),
                    new BigInteger("A0E0E6235E8C93ED947252D9C0BF3EA241A0664E3443FE2D", 16),
                    new BigInteger("25120401793443689936479125511"), NamedGroup.SECP192R1,
                    new BigInteger("EAED9F5D9877E70995534E5ECF03ABEECC02C987F24D3D23", 16));
            case SECP224K1:
                return new TwistedCurvePoint(
                    new BigInteger("E3D3A1F439C39C7B5F950740F3873DCF9735C02B2114ECF1AF687BB5", 16),
                    new BigInteger("2356DDEE0A542911389B6E09BF5574ABE8FF14F2E4DB051C995A25E5", 16),
                    new BigInteger("2077747965710347701281853075092809"), NamedGroup.SECP224K1,
                    new BigInteger("DA7748B4AB209DB506C839D37BBDE023C83385FC16B0D6AD520FCC92", 16));
            case SECP224R1:
                return new TwistedCurvePoint(
                    new BigInteger("8FDC83E56BC637374BA93E363D09CA11E228435223A346C0ECDFCEA8", 16),
                    new BigInteger("B14F991B3EDD7B7DA60B3C739687BD2A96018538FF42A1E939387CD1", 16),
                    new BigInteger("3015283"), NamedGroup.SECP224R1,
                    new BigInteger("E8A543E7CC4318862406F1BA068E2929934EEFCA7D2CD33EDA286D67", 16));
            case SECP256K1:
                return new TwistedCurvePoint(
                    new BigInteger("2217E13B7FA935A7A1ABD7CB74E21CD77D7956379786743AE4FD5569503AD8A6", 16),
                    new BigInteger("DA50FF90EC393E547E7C5013441EF838124D19D1DCF5A3983246C6ECA06F543C", 16),
                    new BigInteger("1013176677300131846900870239606035638738100997248092069256697437031"),
                    NamedGroup.SECP256K1,
                    new BigInteger("5263ECBFDD26F11D2958AF74D50FB0C856AC612DE47A99C87F31F445F3775180", 16));
            case SECP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("A4251D059758E1046D2DD8114F5AD505B718F0455269D747642706E452031CED", 16),
                    new BigInteger("CFE3435B96F62C2365126C1F639F04C8F1C79C470D6887F540FCEACB2B75725", 16),
                    new BigInteger("3317349640749355357762425066592395746459685764401801118712075735758936647"),
                    NamedGroup.SECP256R1,
                    new BigInteger("7F6AA529230D50EBCCF980D5A9D5C6AB2A18C65A4E3C692CCA22B7FA45EC4BB1", 16));
            // case SECP384R1:
            case SECP521R1:
                return new TwistedCurvePoint(new BigInteger(
                    "15279C1FF071496812981BA1EFDD874B368E1942A7E70C4DF7F47715D5A18B2C4B240276A3BEFBD02A1E68EF3B5B55849BFECB272CE3A4D27EA2810A007F32E1174",
                    16),
                    new BigInteger(
                        "1E76482E601360E3E995084036865585164BC0909FB260D55F6B5C1EB0CF9579BC3C1068510B04D193DD5EAD1C89BAF2A381C4B8034EE624C3296A5570701705DA9",
                        16),
                    new BigInteger("69697531"), NamedGroup.SECP521R1,
                    new BigInteger(
                        "F118ECBC0BFDB3676FBBC6F9A70ABDE9863FCEB57341FB7422CDCE9A5676778639D2D00F97511CBCF73DCAB505B92B5D9338B924D13FA44FF99959439CABC9EB6A",
                        16));
            case BRAINPOOLP256R1:
                return new TwistedCurvePoint(
                    new BigInteger("A908140B237E3C712E36E02AC5872FB71215CF93D789EF01549AE274832A49F3", 16),
                    new BigInteger("1CCD6EB649E0246A4B4E5A673DCC8729ED383FAC14C2E998D00191CF325D1935", 16),
                    new BigInteger("492167257"), NamedGroup.BRAINPOOLP256R1,
                    new BigInteger("828F4D0007339B5DB9AEDBB74FF7DC5E8B6B13681F38CB71394FFF06BAD2B1C5", 16));
            case BRAINPOOLP384R1:
                return new TwistedCurvePoint(new BigInteger(
                    "45FE036614DA18CC0145E6D9935F11DA1C754FC168F8035886EF30DBD2ACFC21A2E43C72D1A1C8E3D68E15B296A55AC7",
                    16),
                    new BigInteger(
                        "2E806D2A76BD20EEC948C02742939C7BD804CA98426E0F5D12FA436604D2A0C0F4A2B33C3B4AE9F9CD99D2F8620CFC50",
                        16),
                    new BigInteger("125972502705620325124785968921221517"), NamedGroup.BRAINPOOLP384R1,
                    new BigInteger(
                        "41F93DD138A6F7BF59A02048B03A8C15E385439AFA1960E5E3EC0714931CDD06042D2521E37652AD352B3D8BFFDCD162",
                        16));
            case BRAINPOOLP512R1:
                return new TwistedCurvePoint(new BigInteger(
                    "46B8D7C23CBBA9130A85AC798A7064DA181BC10DBCD91D33E3D5A9605B53F32780BF258EEF84B6D2E915C490C2BCE6E353D7309E4A673EF87ACDC7AA78B38BA8",
                    16),
                    new BigInteger(
                        "92F727276A1A89F1820E5D4045399EA6383594A78BB9ED731B8877F2A45EFB24B8FE8B4630CFF6D6B01B1DE799262C70AE1EA9AF5D4C3BE41FC21BABD8D49564",
                        16),
                    new BigInteger("575369"), NamedGroup.BRAINPOOLP512R1,
                    new BigInteger(
                        "38CCCD284EED12D74A7ECA8980BE126085292D233D3CAF3B9040C92C8B3758F7A65C1669262755C6105A582878F4ED56A9402ECBD505B83581E8E8482B5EDAA6",
                        16));
            default:
                return null;
        }
    }

    /**
     * @return the d
     */
    public BigInteger getPointD() {
        return pointD;
    }

    /**
     * @param d
     *          the d to set
     */
    public void setPointD(BigInteger d) {
        this.pointD = d;
    }

    /**
     * @return the publicPointBaseX
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX
     *                         the publicPointBaseX to set
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
     *                         the publicPointBaseY to set
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
     *                           the intendedNamedGroup to set
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
     *              the order to set
     */
    public void setOrder(BigInteger order) {
        this.order = order;
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
}
