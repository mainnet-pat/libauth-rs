use super::base58_address::{
    decode_base58_address, encode_base58_address_format, Base58AddressFormatVersion,
    Base58AddressNetwork,
};
use super::cash_address::{
    decode_cash_address, encode_cash_address, CashAddressEncodingError, CashAddressResult,
    CashAddressType,
};
use crate::vm::OpcodesBch;

/// The common address types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockingBytecodeType {
    P2pk,
    P2pkh,
    P2sh20,
    P2sh32,
}

/// libauth's `KnownAddressTypeContents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownAddressTypeContents {
    pub r#type: LockingBytecodeType,
    pub payload: Vec<u8>,
}

/// libauth's `UnknownAddressTypeContents`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownAddressTypeContents {
    pub payload: Vec<u8>,
}

pub fn is_pay_to_public_key_uncompressed(locking_bytecode: &[u8]) -> bool {
    locking_bytecode.len() == 67
        && locking_bytecode[0] == OpcodesBch::OP_PUSHBYTES_65
        && locking_bytecode[66] == OpcodesBch::OP_CHECKSIG
}

pub fn is_pay_to_public_key_compressed(locking_bytecode: &[u8]) -> bool {
    locking_bytecode.len() == 35
        && locking_bytecode[0] == OpcodesBch::OP_PUSHBYTES_33
        && locking_bytecode[34] == OpcodesBch::OP_CHECKSIG
}

pub fn is_pay_to_public_key(locking_bytecode: &[u8]) -> bool {
    is_pay_to_public_key_compressed(locking_bytecode)
        || is_pay_to_public_key_uncompressed(locking_bytecode)
}

pub fn is_pay_to_public_key_hash(locking_bytecode: &[u8]) -> bool {
    locking_bytecode.len() == 25
        && locking_bytecode[0] == OpcodesBch::OP_DUP
        && locking_bytecode[1] == OpcodesBch::OP_HASH160
        && locking_bytecode[2] == OpcodesBch::OP_PUSHBYTES_20
        && locking_bytecode[23] == OpcodesBch::OP_EQUALVERIFY
        && locking_bytecode[24] == OpcodesBch::OP_CHECKSIG
}

pub fn is_pay_to_script_hash20(locking_bytecode: &[u8]) -> bool {
    locking_bytecode.len() == 23
        && locking_bytecode[0] == OpcodesBch::OP_HASH160
        && locking_bytecode[1] == OpcodesBch::OP_PUSHBYTES_20
        && locking_bytecode[22] == OpcodesBch::OP_EQUAL
}

pub fn is_pay_to_script_hash32(locking_bytecode: &[u8]) -> bool {
    locking_bytecode.len() == 35
        && locking_bytecode[0] == OpcodesBch::OP_HASH256
        && locking_bytecode[1] == OpcodesBch::OP_PUSHBYTES_32
        && locking_bytecode[34] == OpcodesBch::OP_EQUAL
}

/// The contents of an address's locking bytecode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressContents {
    Known {
        r#type: LockingBytecodeType,
        payload: Vec<u8>,
    },
    Unknown {
        payload: Vec<u8>,
    },
}

/// Match a locking bytecode to a standard address type.
pub fn locking_bytecode_to_address_contents(bytecode: &[u8]) -> AddressContents {
    if is_pay_to_public_key_hash(bytecode) {
        return AddressContents::Known {
            r#type: LockingBytecodeType::P2pkh,
            payload: bytecode[3..23].to_vec(),
        };
    }
    if is_pay_to_script_hash20(bytecode) {
        return AddressContents::Known {
            r#type: LockingBytecodeType::P2sh20,
            payload: bytecode[2..22].to_vec(),
        };
    }
    if is_pay_to_script_hash32(bytecode) {
        return AddressContents::Known {
            r#type: LockingBytecodeType::P2sh32,
            payload: bytecode[2..34].to_vec(),
        };
    }
    if is_pay_to_public_key_uncompressed(bytecode) {
        return AddressContents::Known {
            r#type: LockingBytecodeType::P2pk,
            payload: bytecode[1..66].to_vec(),
        };
    }
    if is_pay_to_public_key_compressed(bytecode) {
        return AddressContents::Known {
            r#type: LockingBytecodeType::P2pk,
            payload: bytecode[1..34].to_vec(),
        };
    }
    AddressContents::Unknown {
        payload: bytecode.to_vec(),
    }
}

/// Encode a P2PKH locking bytecode.
pub fn encode_locking_bytecode_p2pkh(public_key_hash: &[u8]) -> Vec<u8> {
    let mut result = vec![OpcodesBch::OP_DUP, OpcodesBch::OP_HASH160, OpcodesBch::OP_PUSHBYTES_20];
    result.extend_from_slice(public_key_hash);
    result.push(OpcodesBch::OP_EQUALVERIFY);
    result.push(OpcodesBch::OP_CHECKSIG);
    result
}

/// Encode a P2SH20 locking bytecode.
pub fn encode_locking_bytecode_p2sh20(p2sh20_hash: &[u8]) -> Vec<u8> {
    let mut result = vec![OpcodesBch::OP_HASH160, OpcodesBch::OP_PUSHBYTES_20];
    result.extend_from_slice(p2sh20_hash);
    result.push(OpcodesBch::OP_EQUAL);
    result
}

/// Encode a P2SH32 locking bytecode.
pub fn encode_locking_bytecode_p2sh32(p2sh32_hash: &[u8]) -> Vec<u8> {
    let mut result = vec![OpcodesBch::OP_HASH256, OpcodesBch::OP_PUSHBYTES_32];
    result.extend_from_slice(p2sh32_hash);
    result.push(OpcodesBch::OP_EQUAL);
    result
}

/// Encode a P2PK locking bytecode.
pub fn encode_locking_bytecode_p2pk(public_key: &[u8]) -> Vec<u8> {
    let mut result = vec![if public_key.len() == 33 {
        OpcodesBch::OP_PUSHBYTES_33
    } else {
        OpcodesBch::OP_PUSHBYTES_65
    }];
    result.extend_from_slice(public_key);
    result.push(OpcodesBch::OP_CHECKSIG);
    result
}
/// The locking bytecode and network prefix decoded from a CashAddress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedCashAddressLockingBytecode {
    pub bytecode: Vec<u8>,
    pub prefix: String,
    pub token_support: bool,
}

/// The locking bytecode and address version decoded from a Base58Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBase58AddressLockingBytecode {
    pub bytecode: Vec<u8>,
    pub version: Base58AddressFormatVersion,
}

/// The result of encoding locking bytecode as a Base58Address.
///
/// Standard P2PKH and P2SH20 locking bytecode encodes to an address; any other
/// locking bytecode is returned as [`AddressContents`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Base58AddressEncodingResult {
    Address(String),
    Contents(AddressContents),
}

/// Get the locking bytecode for known [`AddressContents`].
pub fn address_contents_to_locking_bytecode(contents: &AddressContents) -> Result<Vec<u8>, String> {
    match contents {
        AddressContents::Known {
            r#type: LockingBytecodeType::P2pkh,
            payload,
        } => Ok(encode_locking_bytecode_p2pkh(payload)),
        AddressContents::Known {
            r#type: LockingBytecodeType::P2sh20,
            payload,
        } => Ok(encode_locking_bytecode_p2sh20(payload)),
        AddressContents::Known {
            r#type: LockingBytecodeType::P2sh32,
            payload,
        } => Ok(encode_locking_bytecode_p2sh32(payload)),
        AddressContents::Known {
            r#type: LockingBytecodeType::P2pk,
            payload,
        } => Ok(encode_locking_bytecode_p2pk(payload)),
        AddressContents::Unknown { .. } => {
            Err("Unrecognized addressContents type: unknown".to_string())
        }
    }
}

/// Encode a locking bytecode as a CashAddress.
///
/// If `bytecode` matches a standard pattern, it is encoded using the proper
/// address type. Otherwise, an error message is returned.
pub fn locking_bytecode_to_cash_address(
    prefix: Option<&str>,
    bytecode: &[u8],
    token_support: Option<bool>,
) -> Result<CashAddressResult, String> {
    let prefix = prefix.unwrap_or("bitcoincash");
    let token_support = token_support.unwrap_or(false);
    match locking_bytecode_to_address_contents(bytecode) {
        AddressContents::Known {
            r#type: LockingBytecodeType::P2pkh,
            payload,
        } => encode_cash_address(
            &payload,
            Some(prefix),
            if token_support {
                CashAddressType::P2pkhWithTokens
            } else {
                CashAddressType::P2pkh
            },
        ),
        AddressContents::Known {
            r#type: LockingBytecodeType::P2sh20 | LockingBytecodeType::P2sh32,
            payload,
        } => encode_cash_address(
            &payload,
            Some(prefix),
            if token_support {
                CashAddressType::P2shWithTokens
            } else {
                CashAddressType::P2sh
            },
        ),
        AddressContents::Known {
            r#type: LockingBytecodeType::P2pk,
            ..
        } => Err(CashAddressEncodingError::NoTypeBitsValueStandardizedForP2pk
            .as_str()
            .to_string()),
        AddressContents::Unknown { .. } => {
            Err(CashAddressEncodingError::UnknownLockingBytecodeType
                .as_str()
                .to_string())
        }
    }
}

/// Convert a CashAddress to its respective locking bytecode.
pub fn cash_address_to_locking_bytecode(
    address: &str,
) -> Result<DecodedCashAddressLockingBytecode, String> {
    let decoded = decode_cash_address(address)?;
    let token_support = matches!(
        decoded.address_type,
        CashAddressType::P2pkhWithTokens | CashAddressType::P2shWithTokens
    );
    let bytecode = match decoded.address_type {
        CashAddressType::P2pkh | CashAddressType::P2pkhWithTokens => {
            encode_locking_bytecode_p2pkh(&decoded.payload)
        }
        CashAddressType::P2sh | CashAddressType::P2shWithTokens => {
            if decoded.payload.len() == 32 {
                encode_locking_bytecode_p2sh32(&decoded.payload)
            } else {
                encode_locking_bytecode_p2sh20(&decoded.payload)
            }
        }
    };
    Ok(DecodedCashAddressLockingBytecode {
        bytecode,
        prefix: decoded.prefix,
        token_support,
    })
}

fn base58_version_for_network(
    network: Base58AddressNetwork,
    address_type: LockingBytecodeType,
) -> Base58AddressFormatVersion {
    match (address_type, network) {
        (LockingBytecodeType::P2pkh, Base58AddressNetwork::Mainnet) => {
            Base58AddressFormatVersion::P2pkh
        }
        (LockingBytecodeType::P2pkh, Base58AddressNetwork::Testnet) => {
            Base58AddressFormatVersion::P2pkhTestnet
        }
        (LockingBytecodeType::P2pkh, Base58AddressNetwork::CopayBch) => {
            Base58AddressFormatVersion::P2pkhCopayBch
        }
        (LockingBytecodeType::P2sh20, Base58AddressNetwork::Mainnet) => {
            Base58AddressFormatVersion::P2sh20
        }
        (LockingBytecodeType::P2sh20, Base58AddressNetwork::Testnet) => {
            Base58AddressFormatVersion::P2sh20Testnet
        }
        (LockingBytecodeType::P2sh20, Base58AddressNetwork::CopayBch) => {
            Base58AddressFormatVersion::P2sh20CopayBch
        }
        (LockingBytecodeType::P2sh32 | LockingBytecodeType::P2pk, _) => {
            Base58AddressFormatVersion::P2pkh
        }
    }
}

/// Encode a locking bytecode as a Base58Address for a given network.
pub fn locking_bytecode_to_base58_address(
    bytecode: &[u8],
    network: Option<Base58AddressNetwork>,
    sha256: Option<&crate::crypto::Sha256>,
) -> Base58AddressEncodingResult {
    let network = network.unwrap_or(Base58AddressNetwork::Mainnet);
    let contents = locking_bytecode_to_address_contents(bytecode);
    match &contents {
        AddressContents::Known {
            r#type: address_type @ (LockingBytecodeType::P2pkh | LockingBytecodeType::P2sh20),
            payload,
        } => Base58AddressEncodingResult::Address(encode_base58_address_format(
            base58_version_for_network(network, *address_type).to_u8(),
            payload,
            sha256,
        )),
        _ => Base58AddressEncodingResult::Contents(contents),
    }
}

/// Convert a Base58Address to its respective locking bytecode.
pub fn base58_address_to_locking_bytecode(
    address: &str,
    sha256: Option<&crate::crypto::Sha256>,
) -> Result<DecodedBase58AddressLockingBytecode, String> {
    let decoded = decode_base58_address(address, sha256)?;
    let address_type = if decoded.version.is_p2pkh() {
        LockingBytecodeType::P2pkh
    } else {
        LockingBytecodeType::P2sh20
    };
    Ok(DecodedBase58AddressLockingBytecode {
        bytecode: address_contents_to_locking_bytecode(&AddressContents::Known {
            r#type: address_type,
            payload: decoded.payload,
        })?,
        version: decoded.version,
    })
}
