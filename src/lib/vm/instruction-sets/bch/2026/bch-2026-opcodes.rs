/// The opcodes added to the `BCH_2026_05` instruction set beyond those present in
/// `BCH_2023_05`.
pub struct OpcodesBch2026Additions;

impl OpcodesBch2026Additions {
    /// Formerly `OP_VERIF`
    pub const OP_BEGIN: u8 = 0x65;
    /// Formerly `OP_VERNOTIF`
    pub const OP_UNTIL: u8 = 0x66;
    pub const OP_INVERT: u8 = 0x83;
    /// Formerly `OP_RESERVED1`
    pub const OP_DEFINE: u8 = 0x89;
    /// Formerly `OP_RESERVED2`
    pub const OP_INVOKE: u8 = 0x8a;
    /// Formerly `OP_2MUL`
    pub const OP_LSHIFTNUM: u8 = 0x8d;
    /// Formerly `OP_2DIV`
    pub const OP_RSHIFTNUM: u8 = 0x8e;
    /// Formerly `OP_LSHIFT`
    pub const OP_LSHIFTBIN: u8 = 0x98;
    /// Formerly `OP_RSHIFT`
    pub const OP_RSHIFTBIN: u8 = 0x99;

    /// The members of this enum in declaration order (the forward mapping of
    /// the TypeScript enum object; later members win reverse lookups).
    pub const MEMBERS: &'static [(&'static str, u8)] = &[
        ("OP_BEGIN", 0x65),
        ("OP_UNTIL", 0x66),
        ("OP_INVERT", 0x83),
        ("OP_DEFINE", 0x89),
        ("OP_INVOKE", 0x8a),
        ("OP_LSHIFTNUM", 0x8d),
        ("OP_RSHIFTNUM", 0x8e),
        ("OP_LSHIFTBIN", 0x98),
        ("OP_RSHIFTBIN", 0x99),
    ];
}

/// The `BCH_SPEC` instruction set.
///
/// Note: to maximize script compilation compatibility, this instruction set also
/// includes the previous names for new opcodes (e.g. `OP_VERIF` for `OP_BEGIN`).
pub struct OpcodesBch2026;

impl OpcodesBch2026 {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHBYTES_1: u8 = 0x01;
    pub const OP_PUSHBYTES_2: u8 = 0x02;
    pub const OP_PUSHBYTES_3: u8 = 0x03;
    pub const OP_PUSHBYTES_4: u8 = 0x04;
    pub const OP_PUSHBYTES_5: u8 = 0x05;
    pub const OP_PUSHBYTES_6: u8 = 0x06;
    pub const OP_PUSHBYTES_7: u8 = 0x07;
    pub const OP_PUSHBYTES_8: u8 = 0x08;
    pub const OP_PUSHBYTES_9: u8 = 0x09;
    pub const OP_PUSHBYTES_10: u8 = 0x0a;
    pub const OP_PUSHBYTES_11: u8 = 0x0b;
    pub const OP_PUSHBYTES_12: u8 = 0x0c;
    pub const OP_PUSHBYTES_13: u8 = 0x0d;
    pub const OP_PUSHBYTES_14: u8 = 0x0e;
    pub const OP_PUSHBYTES_15: u8 = 0x0f;
    pub const OP_PUSHBYTES_16: u8 = 0x10;
    pub const OP_PUSHBYTES_17: u8 = 0x11;
    pub const OP_PUSHBYTES_18: u8 = 0x12;
    pub const OP_PUSHBYTES_19: u8 = 0x13;
    pub const OP_PUSHBYTES_20: u8 = 0x14;
    pub const OP_PUSHBYTES_21: u8 = 0x15;
    pub const OP_PUSHBYTES_22: u8 = 0x16;
    pub const OP_PUSHBYTES_23: u8 = 0x17;
    pub const OP_PUSHBYTES_24: u8 = 0x18;
    pub const OP_PUSHBYTES_25: u8 = 0x19;
    pub const OP_PUSHBYTES_26: u8 = 0x1a;
    pub const OP_PUSHBYTES_27: u8 = 0x1b;
    pub const OP_PUSHBYTES_28: u8 = 0x1c;
    pub const OP_PUSHBYTES_29: u8 = 0x1d;
    pub const OP_PUSHBYTES_30: u8 = 0x1e;
    pub const OP_PUSHBYTES_31: u8 = 0x1f;
    pub const OP_PUSHBYTES_32: u8 = 0x20;
    pub const OP_PUSHBYTES_33: u8 = 0x21;
    pub const OP_PUSHBYTES_34: u8 = 0x22;
    pub const OP_PUSHBYTES_35: u8 = 0x23;
    pub const OP_PUSHBYTES_36: u8 = 0x24;
    pub const OP_PUSHBYTES_37: u8 = 0x25;
    pub const OP_PUSHBYTES_38: u8 = 0x26;
    pub const OP_PUSHBYTES_39: u8 = 0x27;
    pub const OP_PUSHBYTES_40: u8 = 0x28;
    pub const OP_PUSHBYTES_41: u8 = 0x29;
    pub const OP_PUSHBYTES_42: u8 = 0x2a;
    pub const OP_PUSHBYTES_43: u8 = 0x2b;
    pub const OP_PUSHBYTES_44: u8 = 0x2c;
    pub const OP_PUSHBYTES_45: u8 = 0x2d;
    pub const OP_PUSHBYTES_46: u8 = 0x2e;
    pub const OP_PUSHBYTES_47: u8 = 0x2f;
    pub const OP_PUSHBYTES_48: u8 = 0x30;
    pub const OP_PUSHBYTES_49: u8 = 0x31;
    pub const OP_PUSHBYTES_50: u8 = 0x32;
    pub const OP_PUSHBYTES_51: u8 = 0x33;
    pub const OP_PUSHBYTES_52: u8 = 0x34;
    pub const OP_PUSHBYTES_53: u8 = 0x35;
    pub const OP_PUSHBYTES_54: u8 = 0x36;
    pub const OP_PUSHBYTES_55: u8 = 0x37;
    pub const OP_PUSHBYTES_56: u8 = 0x38;
    pub const OP_PUSHBYTES_57: u8 = 0x39;
    pub const OP_PUSHBYTES_58: u8 = 0x3a;
    pub const OP_PUSHBYTES_59: u8 = 0x3b;
    pub const OP_PUSHBYTES_60: u8 = 0x3c;
    pub const OP_PUSHBYTES_61: u8 = 0x3d;
    pub const OP_PUSHBYTES_62: u8 = 0x3e;
    pub const OP_PUSHBYTES_63: u8 = 0x3f;
    pub const OP_PUSHBYTES_64: u8 = 0x40;
    pub const OP_PUSHBYTES_65: u8 = 0x41;
    pub const OP_PUSHBYTES_66: u8 = 0x42;
    pub const OP_PUSHBYTES_67: u8 = 0x43;
    pub const OP_PUSHBYTES_68: u8 = 0x44;
    pub const OP_PUSHBYTES_69: u8 = 0x45;
    pub const OP_PUSHBYTES_70: u8 = 0x46;
    pub const OP_PUSHBYTES_71: u8 = 0x47;
    pub const OP_PUSHBYTES_72: u8 = 0x48;
    pub const OP_PUSHBYTES_73: u8 = 0x49;
    pub const OP_PUSHBYTES_74: u8 = 0x4a;
    pub const OP_PUSHBYTES_75: u8 = 0x4b;
    pub const OP_PUSHDATA_1: u8 = 0x4c;
    pub const OP_PUSHDATA_2: u8 = 0x4d;
    pub const OP_PUSHDATA_4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_RESERVED: u8 = 0x50;
    pub const OP_1: u8 = 0x51;
    pub const OP_2: u8 = 0x52;
    pub const OP_3: u8 = 0x53;
    pub const OP_4: u8 = 0x54;
    pub const OP_5: u8 = 0x55;
    pub const OP_6: u8 = 0x56;
    pub const OP_7: u8 = 0x57;
    pub const OP_8: u8 = 0x58;
    pub const OP_9: u8 = 0x59;
    pub const OP_10: u8 = 0x5a;
    pub const OP_11: u8 = 0x5b;
    pub const OP_12: u8 = 0x5c;
    pub const OP_13: u8 = 0x5d;
    pub const OP_14: u8 = 0x5e;
    pub const OP_15: u8 = 0x5f;
    pub const OP_16: u8 = 0x60;
    pub const OP_NOP: u8 = 0x61;
    pub const OP_VER: u8 = 0x62;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_VERIF: u8 = 0x65;
    pub const OP_VERNOTIF: u8 = 0x66;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_TOALTSTACK: u8 = 0x6b;
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    pub const OP_2DROP: u8 = 0x6d;
    pub const OP_2DUP: u8 = 0x6e;
    pub const OP_3DUP: u8 = 0x6f;
    pub const OP_2OVER: u8 = 0x70;
    pub const OP_2ROT: u8 = 0x71;
    pub const OP_2SWAP: u8 = 0x72;
    pub const OP_IFDUP: u8 = 0x73;
    pub const OP_DEPTH: u8 = 0x74;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_NIP: u8 = 0x77;
    pub const OP_OVER: u8 = 0x78;
    pub const OP_PICK: u8 = 0x79;
    pub const OP_ROLL: u8 = 0x7a;
    pub const OP_ROT: u8 = 0x7b;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_TUCK: u8 = 0x7d;
    pub const OP_CAT: u8 = 0x7e;
    pub const OP_SPLIT: u8 = 0x7f;
    pub const OP_NUM2BIN: u8 = 0x80;
    pub const OP_BIN2NUM: u8 = 0x81;
    pub const OP_SIZE: u8 = 0x82;
    pub const OP_INVERT: u8 = 0x83;
    pub const OP_AND: u8 = 0x84;
    pub const OP_OR: u8 = 0x85;
    pub const OP_XOR: u8 = 0x86;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_RESERVED1: u8 = 0x89;
    pub const OP_RESERVED2: u8 = 0x8a;
    pub const OP_1ADD: u8 = 0x8b;
    pub const OP_1SUB: u8 = 0x8c;
    pub const OP_2MUL: u8 = 0x8d;
    pub const OP_2DIV: u8 = 0x8e;
    pub const OP_NEGATE: u8 = 0x8f;
    pub const OP_ABS: u8 = 0x90;
    pub const OP_NOT: u8 = 0x91;
    pub const OP_0NOTEQUAL: u8 = 0x92;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_SUB: u8 = 0x94;
    pub const OP_MUL: u8 = 0x95;
    pub const OP_DIV: u8 = 0x96;
    pub const OP_MOD: u8 = 0x97;
    pub const OP_LSHIFT: u8 = 0x98;
    pub const OP_RSHIFT: u8 = 0x99;
    pub const OP_BOOLAND: u8 = 0x9a;
    pub const OP_BOOLOR: u8 = 0x9b;
    pub const OP_NUMEQUAL: u8 = 0x9c;
    pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
    pub const OP_NUMNOTEQUAL: u8 = 0x9e;
    pub const OP_LESSTHAN: u8 = 0x9f;
    pub const OP_GREATERTHAN: u8 = 0xa0;
    pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
    pub const OP_MIN: u8 = 0xa3;
    pub const OP_MAX: u8 = 0xa4;
    pub const OP_WITHIN: u8 = 0xa5;
    pub const OP_RIPEMD160: u8 = 0xa6;
    pub const OP_SHA1: u8 = 0xa7;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    pub const OP_CODESEPARATOR: u8 = 0xab;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
    pub const OP_NOP1: u8 = 0xb0;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
    pub const OP_NOP4: u8 = 0xb3;
    pub const OP_NOP5: u8 = 0xb4;
    pub const OP_NOP6: u8 = 0xb5;
    pub const OP_NOP7: u8 = 0xb6;
    pub const OP_NOP8: u8 = 0xb7;
    pub const OP_NOP9: u8 = 0xb8;
    pub const OP_NOP10: u8 = 0xb9;
    pub const OP_CHECKDATASIG: u8 = 0xba;
    pub const OP_CHECKDATASIGVERIFY: u8 = 0xbb;
    pub const OP_REVERSEBYTES: u8 = 0xbc;
    pub const OP_UNKNOWN189: u8 = 0xbd;
    pub const OP_UNKNOWN190: u8 = 0xbe;
    pub const OP_UNKNOWN191: u8 = 0xbf;
    pub const OP_INPUTINDEX: u8 = 0xc0;
    pub const OP_ACTIVEBYTECODE: u8 = 0xc1;
    pub const OP_TXVERSION: u8 = 0xc2;
    pub const OP_TXINPUTCOUNT: u8 = 0xc3;
    pub const OP_TXOUTPUTCOUNT: u8 = 0xc4;
    pub const OP_TXLOCKTIME: u8 = 0xc5;
    pub const OP_UTXOVALUE: u8 = 0xc6;
    pub const OP_UTXOBYTECODE: u8 = 0xc7;
    pub const OP_OUTPOINTTXHASH: u8 = 0xc8;
    pub const OP_OUTPOINTINDEX: u8 = 0xc9;
    pub const OP_INPUTBYTECODE: u8 = 0xca;
    pub const OP_INPUTSEQUENCENUMBER: u8 = 0xcb;
    pub const OP_OUTPUTVALUE: u8 = 0xcc;
    pub const OP_OUTPUTBYTECODE: u8 = 0xcd;
    pub const OP_UTXOTOKENCATEGORY: u8 = 0xce;
    pub const OP_UTXOTOKENCOMMITMENT: u8 = 0xcf;
    pub const OP_UTXOTOKENAMOUNT: u8 = 0xd0;
    pub const OP_OUTPUTTOKENCATEGORY: u8 = 0xd1;
    pub const OP_OUTPUTTOKENCOMMITMENT: u8 = 0xd2;
    pub const OP_OUTPUTTOKENAMOUNT: u8 = 0xd3;
    pub const OP_UNKNOWN212: u8 = 0xd4;
    pub const OP_UNKNOWN213: u8 = 0xd5;
    pub const OP_UNKNOWN214: u8 = 0xd6;
    pub const OP_UNKNOWN215: u8 = 0xd7;
    pub const OP_UNKNOWN216: u8 = 0xd8;
    pub const OP_UNKNOWN217: u8 = 0xd9;
    pub const OP_UNKNOWN218: u8 = 0xda;
    pub const OP_UNKNOWN219: u8 = 0xdb;
    pub const OP_UNKNOWN220: u8 = 0xdc;
    pub const OP_UNKNOWN221: u8 = 0xdd;
    pub const OP_UNKNOWN222: u8 = 0xde;
    pub const OP_UNKNOWN223: u8 = 0xdf;
    pub const OP_UNKNOWN224: u8 = 0xe0;
    pub const OP_UNKNOWN225: u8 = 0xe1;
    pub const OP_UNKNOWN226: u8 = 0xe2;
    pub const OP_UNKNOWN227: u8 = 0xe3;
    pub const OP_UNKNOWN228: u8 = 0xe4;
    pub const OP_UNKNOWN229: u8 = 0xe5;
    pub const OP_UNKNOWN230: u8 = 0xe6;
    pub const OP_UNKNOWN231: u8 = 0xe7;
    pub const OP_UNKNOWN232: u8 = 0xe8;
    pub const OP_UNKNOWN233: u8 = 0xe9;
    pub const OP_UNKNOWN234: u8 = 0xea;
    pub const OP_UNKNOWN235: u8 = 0xeb;
    pub const OP_UNKNOWN236: u8 = 0xec;
    pub const OP_UNKNOWN237: u8 = 0xed;
    pub const OP_UNKNOWN238: u8 = 0xee;
    pub const OP_UNKNOWN239: u8 = 0xef;
    pub const OP_UNKNOWN240: u8 = 0xf0;
    pub const OP_UNKNOWN241: u8 = 0xf1;
    pub const OP_UNKNOWN242: u8 = 0xf2;
    pub const OP_UNKNOWN243: u8 = 0xf3;
    pub const OP_UNKNOWN244: u8 = 0xf4;
    pub const OP_UNKNOWN245: u8 = 0xf5;
    pub const OP_UNKNOWN246: u8 = 0xf6;
    pub const OP_UNKNOWN247: u8 = 0xf7;
    pub const OP_UNKNOWN248: u8 = 0xf8;
    pub const OP_UNKNOWN249: u8 = 0xf9;
    pub const OP_UNKNOWN250: u8 = 0xfa;
    pub const OP_UNKNOWN251: u8 = 0xfb;
    pub const OP_UNKNOWN252: u8 = 0xfc;
    pub const OP_UNKNOWN253: u8 = 0xfd;
    pub const OP_UNKNOWN254: u8 = 0xfe;
    pub const OP_UNKNOWN255: u8 = 0xff;
    pub const OP_BEGIN: u8 = 0x65;
    pub const OP_UNTIL: u8 = 0x66;
    pub const OP_DEFINE: u8 = 0x89;
    pub const OP_INVOKE: u8 = 0x8a;
    pub const OP_LSHIFTNUM: u8 = 0x8d;
    pub const OP_RSHIFTNUM: u8 = 0x8e;
    pub const OP_LSHIFTBIN: u8 = 0x98;
    pub const OP_RSHIFTBIN: u8 = 0x99;

    /// The members of this enum in declaration order (the forward mapping of
    /// the TypeScript enum object; later members win reverse lookups).
    pub const MEMBERS: &'static [(&'static str, u8)] = &[
        ("OP_0", 0x00),
        ("OP_PUSHBYTES_1", 0x01),
        ("OP_PUSHBYTES_2", 0x02),
        ("OP_PUSHBYTES_3", 0x03),
        ("OP_PUSHBYTES_4", 0x04),
        ("OP_PUSHBYTES_5", 0x05),
        ("OP_PUSHBYTES_6", 0x06),
        ("OP_PUSHBYTES_7", 0x07),
        ("OP_PUSHBYTES_8", 0x08),
        ("OP_PUSHBYTES_9", 0x09),
        ("OP_PUSHBYTES_10", 0x0a),
        ("OP_PUSHBYTES_11", 0x0b),
        ("OP_PUSHBYTES_12", 0x0c),
        ("OP_PUSHBYTES_13", 0x0d),
        ("OP_PUSHBYTES_14", 0x0e),
        ("OP_PUSHBYTES_15", 0x0f),
        ("OP_PUSHBYTES_16", 0x10),
        ("OP_PUSHBYTES_17", 0x11),
        ("OP_PUSHBYTES_18", 0x12),
        ("OP_PUSHBYTES_19", 0x13),
        ("OP_PUSHBYTES_20", 0x14),
        ("OP_PUSHBYTES_21", 0x15),
        ("OP_PUSHBYTES_22", 0x16),
        ("OP_PUSHBYTES_23", 0x17),
        ("OP_PUSHBYTES_24", 0x18),
        ("OP_PUSHBYTES_25", 0x19),
        ("OP_PUSHBYTES_26", 0x1a),
        ("OP_PUSHBYTES_27", 0x1b),
        ("OP_PUSHBYTES_28", 0x1c),
        ("OP_PUSHBYTES_29", 0x1d),
        ("OP_PUSHBYTES_30", 0x1e),
        ("OP_PUSHBYTES_31", 0x1f),
        ("OP_PUSHBYTES_32", 0x20),
        ("OP_PUSHBYTES_33", 0x21),
        ("OP_PUSHBYTES_34", 0x22),
        ("OP_PUSHBYTES_35", 0x23),
        ("OP_PUSHBYTES_36", 0x24),
        ("OP_PUSHBYTES_37", 0x25),
        ("OP_PUSHBYTES_38", 0x26),
        ("OP_PUSHBYTES_39", 0x27),
        ("OP_PUSHBYTES_40", 0x28),
        ("OP_PUSHBYTES_41", 0x29),
        ("OP_PUSHBYTES_42", 0x2a),
        ("OP_PUSHBYTES_43", 0x2b),
        ("OP_PUSHBYTES_44", 0x2c),
        ("OP_PUSHBYTES_45", 0x2d),
        ("OP_PUSHBYTES_46", 0x2e),
        ("OP_PUSHBYTES_47", 0x2f),
        ("OP_PUSHBYTES_48", 0x30),
        ("OP_PUSHBYTES_49", 0x31),
        ("OP_PUSHBYTES_50", 0x32),
        ("OP_PUSHBYTES_51", 0x33),
        ("OP_PUSHBYTES_52", 0x34),
        ("OP_PUSHBYTES_53", 0x35),
        ("OP_PUSHBYTES_54", 0x36),
        ("OP_PUSHBYTES_55", 0x37),
        ("OP_PUSHBYTES_56", 0x38),
        ("OP_PUSHBYTES_57", 0x39),
        ("OP_PUSHBYTES_58", 0x3a),
        ("OP_PUSHBYTES_59", 0x3b),
        ("OP_PUSHBYTES_60", 0x3c),
        ("OP_PUSHBYTES_61", 0x3d),
        ("OP_PUSHBYTES_62", 0x3e),
        ("OP_PUSHBYTES_63", 0x3f),
        ("OP_PUSHBYTES_64", 0x40),
        ("OP_PUSHBYTES_65", 0x41),
        ("OP_PUSHBYTES_66", 0x42),
        ("OP_PUSHBYTES_67", 0x43),
        ("OP_PUSHBYTES_68", 0x44),
        ("OP_PUSHBYTES_69", 0x45),
        ("OP_PUSHBYTES_70", 0x46),
        ("OP_PUSHBYTES_71", 0x47),
        ("OP_PUSHBYTES_72", 0x48),
        ("OP_PUSHBYTES_73", 0x49),
        ("OP_PUSHBYTES_74", 0x4a),
        ("OP_PUSHBYTES_75", 0x4b),
        ("OP_PUSHDATA_1", 0x4c),
        ("OP_PUSHDATA_2", 0x4d),
        ("OP_PUSHDATA_4", 0x4e),
        ("OP_1NEGATE", 0x4f),
        ("OP_RESERVED", 0x50),
        ("OP_1", 0x51),
        ("OP_2", 0x52),
        ("OP_3", 0x53),
        ("OP_4", 0x54),
        ("OP_5", 0x55),
        ("OP_6", 0x56),
        ("OP_7", 0x57),
        ("OP_8", 0x58),
        ("OP_9", 0x59),
        ("OP_10", 0x5a),
        ("OP_11", 0x5b),
        ("OP_12", 0x5c),
        ("OP_13", 0x5d),
        ("OP_14", 0x5e),
        ("OP_15", 0x5f),
        ("OP_16", 0x60),
        ("OP_NOP", 0x61),
        ("OP_VER", 0x62),
        ("OP_IF", 0x63),
        ("OP_NOTIF", 0x64),
        ("OP_VERIF", 0x65),
        ("OP_VERNOTIF", 0x66),
        ("OP_ELSE", 0x67),
        ("OP_ENDIF", 0x68),
        ("OP_VERIFY", 0x69),
        ("OP_RETURN", 0x6a),
        ("OP_TOALTSTACK", 0x6b),
        ("OP_FROMALTSTACK", 0x6c),
        ("OP_2DROP", 0x6d),
        ("OP_2DUP", 0x6e),
        ("OP_3DUP", 0x6f),
        ("OP_2OVER", 0x70),
        ("OP_2ROT", 0x71),
        ("OP_2SWAP", 0x72),
        ("OP_IFDUP", 0x73),
        ("OP_DEPTH", 0x74),
        ("OP_DROP", 0x75),
        ("OP_DUP", 0x76),
        ("OP_NIP", 0x77),
        ("OP_OVER", 0x78),
        ("OP_PICK", 0x79),
        ("OP_ROLL", 0x7a),
        ("OP_ROT", 0x7b),
        ("OP_SWAP", 0x7c),
        ("OP_TUCK", 0x7d),
        ("OP_CAT", 0x7e),
        ("OP_SPLIT", 0x7f),
        ("OP_NUM2BIN", 0x80),
        ("OP_BIN2NUM", 0x81),
        ("OP_SIZE", 0x82),
        ("OP_INVERT", 0x83),
        ("OP_AND", 0x84),
        ("OP_OR", 0x85),
        ("OP_XOR", 0x86),
        ("OP_EQUAL", 0x87),
        ("OP_EQUALVERIFY", 0x88),
        ("OP_RESERVED1", 0x89),
        ("OP_RESERVED2", 0x8a),
        ("OP_1ADD", 0x8b),
        ("OP_1SUB", 0x8c),
        ("OP_2MUL", 0x8d),
        ("OP_2DIV", 0x8e),
        ("OP_NEGATE", 0x8f),
        ("OP_ABS", 0x90),
        ("OP_NOT", 0x91),
        ("OP_0NOTEQUAL", 0x92),
        ("OP_ADD", 0x93),
        ("OP_SUB", 0x94),
        ("OP_MUL", 0x95),
        ("OP_DIV", 0x96),
        ("OP_MOD", 0x97),
        ("OP_LSHIFT", 0x98),
        ("OP_RSHIFT", 0x99),
        ("OP_BOOLAND", 0x9a),
        ("OP_BOOLOR", 0x9b),
        ("OP_NUMEQUAL", 0x9c),
        ("OP_NUMEQUALVERIFY", 0x9d),
        ("OP_NUMNOTEQUAL", 0x9e),
        ("OP_LESSTHAN", 0x9f),
        ("OP_GREATERTHAN", 0xa0),
        ("OP_LESSTHANOREQUAL", 0xa1),
        ("OP_GREATERTHANOREQUAL", 0xa2),
        ("OP_MIN", 0xa3),
        ("OP_MAX", 0xa4),
        ("OP_WITHIN", 0xa5),
        ("OP_RIPEMD160", 0xa6),
        ("OP_SHA1", 0xa7),
        ("OP_SHA256", 0xa8),
        ("OP_HASH160", 0xa9),
        ("OP_HASH256", 0xaa),
        ("OP_CODESEPARATOR", 0xab),
        ("OP_CHECKSIG", 0xac),
        ("OP_CHECKSIGVERIFY", 0xad),
        ("OP_CHECKMULTISIG", 0xae),
        ("OP_CHECKMULTISIGVERIFY", 0xaf),
        ("OP_NOP1", 0xb0),
        ("OP_CHECKLOCKTIMEVERIFY", 0xb1),
        ("OP_CHECKSEQUENCEVERIFY", 0xb2),
        ("OP_NOP4", 0xb3),
        ("OP_NOP5", 0xb4),
        ("OP_NOP6", 0xb5),
        ("OP_NOP7", 0xb6),
        ("OP_NOP8", 0xb7),
        ("OP_NOP9", 0xb8),
        ("OP_NOP10", 0xb9),
        ("OP_CHECKDATASIG", 0xba),
        ("OP_CHECKDATASIGVERIFY", 0xbb),
        ("OP_REVERSEBYTES", 0xbc),
        ("OP_UNKNOWN189", 0xbd),
        ("OP_UNKNOWN190", 0xbe),
        ("OP_UNKNOWN191", 0xbf),
        ("OP_INPUTINDEX", 0xc0),
        ("OP_ACTIVEBYTECODE", 0xc1),
        ("OP_TXVERSION", 0xc2),
        ("OP_TXINPUTCOUNT", 0xc3),
        ("OP_TXOUTPUTCOUNT", 0xc4),
        ("OP_TXLOCKTIME", 0xc5),
        ("OP_UTXOVALUE", 0xc6),
        ("OP_UTXOBYTECODE", 0xc7),
        ("OP_OUTPOINTTXHASH", 0xc8),
        ("OP_OUTPOINTINDEX", 0xc9),
        ("OP_INPUTBYTECODE", 0xca),
        ("OP_INPUTSEQUENCENUMBER", 0xcb),
        ("OP_OUTPUTVALUE", 0xcc),
        ("OP_OUTPUTBYTECODE", 0xcd),
        ("OP_UTXOTOKENCATEGORY", 0xce),
        ("OP_UTXOTOKENCOMMITMENT", 0xcf),
        ("OP_UTXOTOKENAMOUNT", 0xd0),
        ("OP_OUTPUTTOKENCATEGORY", 0xd1),
        ("OP_OUTPUTTOKENCOMMITMENT", 0xd2),
        ("OP_OUTPUTTOKENAMOUNT", 0xd3),
        ("OP_UNKNOWN212", 0xd4),
        ("OP_UNKNOWN213", 0xd5),
        ("OP_UNKNOWN214", 0xd6),
        ("OP_UNKNOWN215", 0xd7),
        ("OP_UNKNOWN216", 0xd8),
        ("OP_UNKNOWN217", 0xd9),
        ("OP_UNKNOWN218", 0xda),
        ("OP_UNKNOWN219", 0xdb),
        ("OP_UNKNOWN220", 0xdc),
        ("OP_UNKNOWN221", 0xdd),
        ("OP_UNKNOWN222", 0xde),
        ("OP_UNKNOWN223", 0xdf),
        ("OP_UNKNOWN224", 0xe0),
        ("OP_UNKNOWN225", 0xe1),
        ("OP_UNKNOWN226", 0xe2),
        ("OP_UNKNOWN227", 0xe3),
        ("OP_UNKNOWN228", 0xe4),
        ("OP_UNKNOWN229", 0xe5),
        ("OP_UNKNOWN230", 0xe6),
        ("OP_UNKNOWN231", 0xe7),
        ("OP_UNKNOWN232", 0xe8),
        ("OP_UNKNOWN233", 0xe9),
        ("OP_UNKNOWN234", 0xea),
        ("OP_UNKNOWN235", 0xeb),
        ("OP_UNKNOWN236", 0xec),
        ("OP_UNKNOWN237", 0xed),
        ("OP_UNKNOWN238", 0xee),
        ("OP_UNKNOWN239", 0xef),
        ("OP_UNKNOWN240", 0xf0),
        ("OP_UNKNOWN241", 0xf1),
        ("OP_UNKNOWN242", 0xf2),
        ("OP_UNKNOWN243", 0xf3),
        ("OP_UNKNOWN244", 0xf4),
        ("OP_UNKNOWN245", 0xf5),
        ("OP_UNKNOWN246", 0xf6),
        ("OP_UNKNOWN247", 0xf7),
        ("OP_UNKNOWN248", 0xf8),
        ("OP_UNKNOWN249", 0xf9),
        ("OP_UNKNOWN250", 0xfa),
        ("OP_UNKNOWN251", 0xfb),
        ("OP_UNKNOWN252", 0xfc),
        ("OP_UNKNOWN253", 0xfd),
        ("OP_UNKNOWN254", 0xfe),
        ("OP_UNKNOWN255", 0xff),
        ("OP_BEGIN", 0x65),
        ("OP_UNTIL", 0x66),
        ("OP_DEFINE", 0x89),
        ("OP_INVOKE", 0x8a),
        ("OP_LSHIFTNUM", 0x8d),
        ("OP_RSHIFTNUM", 0x8e),
        ("OP_LSHIFTBIN", 0x98),
        ("OP_RSHIFTBIN", 0x99),
    ];
}
