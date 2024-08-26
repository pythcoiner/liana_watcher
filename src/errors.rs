use std::error::Error as LegacyError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    NoRpc,
    RPCCallFail,
    GetHashFail,
    GetBlockFail,
    GetFirstBlockFail,
    WrongDustLimit,
    CannotConvertScriptToAddress,
    NextBlockNotAvailable,
    UtxoSetBuilderAlreadyInit,
    ActualBlockNotAvailable,
    RpcNotAvailable,
    NotEnoughBalance,
    UnrecognizedScript,
    AddressNotInTree(String),
    NotImplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RPCCallFail => write!(f, "Fail to get an answer from bitcoind RPC!"),
            Error::NoRpc => write!(f, "self.rpc is missing"),
            Error::GetHashFail => write!(f, "rpc get hash failed"),
            Error::GetBlockFail => write!(f, "rpc get block fail"),
            Error::GetFirstBlockFail => write!(f, "Failed to get block #1"),
            Error::WrongDustLimit => write!(f, "Wrong dust limit"),
            Error::NextBlockNotAvailable => write!(f, "Next block not available"),
            Error::UtxoSetBuilderAlreadyInit => write!(f, "Already init"),
            Error::ActualBlockNotAvailable => write!(f, "Actual block missing"),
            Error::RpcNotAvailable => write!(f, "self.rpc is missing"),
            Error::NotEnoughBalance => write!(f, "Not enough balance on address"),
            Error::AddressNotInTree(addr) => write!(f, "Address missing in the tree: {}", addr),
            Error::NotImplemented => write!(f, "Error not yet implemented"),
            _ => write!(f, "Unimplemented error!"),
        }
    }
}

impl LegacyError for Error {}

impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.to_string()
    }
}
