//! Structured error encoding for deterministic mapping to BitChat RustPy exceptions.

use pyo3::exceptions::PyValueError;
use pyo3::PyErr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreErrorKind {
    InvalidPacket,
    PacketEncoding,
    PacketDecoding,
    UnsupportedProtocolVersion,
    UnknownMessageType,
    InvalidFragment,
    FragmentPayload,
    FragmentLimitExceeded,
    Framing,
    Crypto,
    InvalidKey,
    InvalidSignature,
    SignatureVerification,
    KeyExchange,
    Encryption,
    Decryption,
    InvalidNonce,
    Noise,
    NoiseState,
    Replay,
    Authentication,
    Ble,
    BleScan,
    BleConnection,
    BleGatt,
    BleTransport,
    Value,
}

impl CoreErrorKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::InvalidPacket => "InvalidPacketError",
            Self::PacketEncoding => "PacketEncodingError",
            Self::PacketDecoding => "PacketDecodingError",
            Self::UnsupportedProtocolVersion => "UnsupportedProtocolVersionError",
            Self::UnknownMessageType => "UnknownMessageTypeError",
            Self::InvalidFragment => "InvalidFragmentError",
            Self::FragmentPayload => "FragmentPayloadError",
            Self::FragmentLimitExceeded => "FragmentLimitExceededError",
            Self::Framing => "FramingError",
            Self::Crypto => "CryptoError",
            Self::InvalidKey => "InvalidKeyError",
            Self::InvalidSignature => "InvalidSignatureError",
            Self::SignatureVerification => "SignatureVerificationError",
            Self::KeyExchange => "KeyExchangeError",
            Self::Encryption => "EncryptionError",
            Self::Decryption => "DecryptionError",
            Self::InvalidNonce => "InvalidNonceError",
            Self::Noise => "NoiseError",
            Self::NoiseState => "NoiseStateError",
            Self::Replay => "ReplayError",
            Self::Authentication => "AuthenticationError",
            Self::Ble => "BLEError",
            Self::BleScan => "BLEScanError",
            Self::BleConnection => "BLEConnectionError",
            Self::BleGatt => "BLEGATTError",
            Self::BleTransport => "BLETransportError",
            Self::Value => "ValueError",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreError {
    pub kind: CoreErrorKind,
    pub message: String,
}

impl CoreError {
    pub fn new(kind: CoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid_packet(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::InvalidPacket, msg)
    }

    pub fn packet_encoding(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::PacketEncoding, msg)
    }

    pub fn packet_decoding(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::PacketDecoding, msg)
    }

    pub fn unsupported_version(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::UnsupportedProtocolVersion, msg)
    }

    pub fn unknown_message_type(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::UnknownMessageType, msg)
    }

    pub fn invalid_fragment(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::InvalidFragment, msg)
    }

    pub fn fragment_payload(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::FragmentPayload, msg)
    }

    pub fn fragment_limit(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::FragmentLimitExceeded, msg)
    }

    pub fn framing(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Framing, msg)
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Crypto, msg)
    }

    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::InvalidKey, msg)
    }

    pub fn invalid_signature(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::InvalidSignature, msg)
    }

    pub fn signature_verification(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::SignatureVerification, msg)
    }

    pub fn key_exchange(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::KeyExchange, msg)
    }

    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Encryption, msg)
    }

    pub fn decryption(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Decryption, msg)
    }

    pub fn invalid_nonce(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::InvalidNonce, msg)
    }

    pub fn noise(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Noise, msg)
    }

    pub fn noise_state(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::NoiseState, msg)
    }

    pub fn replay(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Replay, msg)
    }

    pub fn authentication(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Authentication, msg)
    }

    pub fn ble(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Ble, msg)
    }

    pub fn ble_scan(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::BleScan, msg)
    }

    pub fn ble_connection(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::BleConnection, msg)
    }

    pub fn ble_gatt(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::BleGatt, msg)
    }

    pub fn ble_transport(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::BleTransport, msg)
    }

    pub fn value_err(msg: impl Into<String>) -> Self {
        Self::new(CoreErrorKind::Value, msg)
    }
}

impl From<CoreError> for PyErr {
    fn from(err: CoreError) -> Self {
        PyValueError::new_err(format!(
            "__BITCHAT_ERR__:{}::{}",
            err.kind.tag(),
            err.message
        ))
    }
}
