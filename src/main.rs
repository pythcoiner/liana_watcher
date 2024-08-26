mod cli;
mod errors;

use bitcoin::{Block, Transaction};
use bitcoincore_rpc::{bitcoin, Auth, Client, RpcApi};
use errors::Error;
use miniscript::bitcoin::PublicKey;
use miniscript::iter::TreeLike;
use miniscript::policy::{Liftable, Semantic};
use miniscript::{ExtParams, Miniscript, Segwitv0, Terminal};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::thread;
use std::time::Duration;

fn u64_to_spin(step: u64) -> String {
    match step % 4 {
        0 => "-".to_string(),
        1 => "\\".to_string(),
        2 => "|".to_string(),
        3 => "/".to_string(),
        4 => "/".to_string(),
        _ => "?".to_string(),
    }
}

fn erase_line() {
    print!("\x1B[1A\x1B[K");
}

struct BlockRunner {
    rpc: Client,
    chain_height: u64,
    fetch_block_height: u64,
}

impl BlockRunner {
    fn new(rpc: Client, start_height: u64) -> Self {
        BlockRunner {
            rpc,
            chain_height: 0u64,
            fetch_block_height: start_height,
        }
    }

    fn fetch_height(&self) -> u64 {
        self.fetch_block_height
    }

    fn fetch_chain_height(&self) -> Result<u64, Error> {
        self.rpc.get_block_count().map_err(|_| Error::RPCCallFail)
    }

    fn init(&mut self) -> Result<(), Error> {
        let mut attempt = 0u64;
        println!("Check if first block received");
        while self.chain_height < self.fetch_block_height {
            attempt = attempt.wrapping_add(1);
            // erase_line();
            println!(
                "Waiting bitcoind to reach start block height ... {}",
                u64_to_spin(attempt)
            );
            match self.fetch_chain_height() {
                Ok(height) => self.chain_height = height,
                Err(e) => println!("Fail to fetch chain height: {}", e),
            }
            thread::sleep(Duration::from_millis(400));
        }
        Ok(())
    }

    fn fetch_block(&self, block_height: u64) -> Result<Block, Error> {
        match self.rpc.get_block_hash(block_height) {
            Ok(hash) => match self.rpc.get_by_id(&hash) {
                Ok(block) => Ok(block),
                Err(e) => {
                    println!("Fail to fetch block {}: {}", &hash, e);
                    Err(Error::GetBlockFail)
                }
            },
            Err(e) => {
                println!("Fail to fetch hash at height {}: {}", block_height, e);
                Err(Error::GetHashFail)
            }
        }
    }

    fn next(&mut self) -> Block {
        while self.chain_height < self.fetch_block_height {
            // erase_line();
            // println!("sync, chain at height {} ...", self.chain_height);
            if let Ok(height) = self.fetch_chain_height() {
                self.chain_height = height;
            } else {
                thread::sleep(Duration::from_millis(100));
            }
        }
        loop {
            // erase_line();
            // println!("fetching block at height {}", self.fetch_block_height);
            match self.fetch_block(self.fetch_block_height) {
                Ok(block) => {
                    self.fetch_block_height += 1;
                    return block;
                }
                Err(e) => {
                    erase_line();
                    println!("Fail to fetch block: {}", e);
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
}

// Primary path
// it's always a single or multisig but never have a timelock
fn is_primary_path<T: miniscript::MiniscriptKey>(policy: &miniscript::policy::Semantic<T>) -> bool {
    match policy {
        Semantic::Key(_) => true,
        Semantic::Thresh(t) => t
            .data()
            .iter()
            .all(|k| matches!(k.as_ref(), Semantic::Key(_))),
        _ => false,
    }
}

// We require the locktime to:
//  - not be disabled
//  - be in number of blocks
//  - be 'clean' / minimal, ie all bits without consensus meaning should be 0
//
// All this is achieved simply through asking for a 16-bit integer, since all the
// above are signaled in leftmost bits.
fn csv_check(csv_value: u32) -> Option<u16> {
    if csv_value > 0 {
        u16::try_from(csv_value).ok()
    } else {
        None
    }
}

// Recovery path
// it's always a single or multisig and always have a timelock
fn is_recovery_path<T: miniscript::MiniscriptKey>(
    policy: &miniscript::policy::Semantic<T>,
) -> (bool, Option<u16>) {
    // The recovery spending path must always be a policy of type `thresh(2, older(x), thresh(n, key1,
    // key2, ..))`. In the special case n == 1, it is only `thresh(2, older(x), key)`. In the
    // special case n == len(keys) (i.e. it's an N-of-N multisig), it is normalized as
    // `thresh(n+1, older(x), key1, key2, ...)`.
    let (k, subs) = match policy {
        Semantic::Thresh(thresh) => (thresh.k(), thresh.clone().into_data()),
        _ => return (false, None),
    };
    if k == 2 && subs.len() == 2 {
        // The general case (as well as the n == 1 case). The sub that is not the timelock is
        // of the same form as a primary path.
        let tl_value = subs.iter().find_map(|s| match s.as_ref() {
            Semantic::Older(val) => csv_check(val.to_consensus_u32()),
            _ => None,
        });
        let tl_value = match tl_value {
            Some(v) => v,
            None => return (false, None),
        };
        let keys_sub = subs.into_iter().find(|sub| is_primary_path(sub.as_ref()));
        if keys_sub.is_some() {
            (true, Some(tl_value))
        } else {
            (false, None)
        }
    } else if k == subs.len() && subs.len() > 2 {
        // The N-of-N case. All subs but the threshold must be keys (if one had been thresh()
        // of keys it would have been normalized).
        let mut tl_value = None;
        let mut keys = Vec::with_capacity(subs.len());
        for sub in subs {
            match sub.as_ref() {
                Semantic::Key(key) => keys.push(key.clone()),
                Semantic::Older(val) => {
                    if tl_value.is_some() {
                        // Must have only one timelock
                        return (false, None);
                    }
                    tl_value = csv_check(val.to_consensus_u32());
                }
                _ => return (false, None),
            }
        }
        if keys.len() < 2 {
            return (false, None);
        }
        (true, tl_value)
    } else {
        // If there is less than 2 subs, there can't be both a timelock and keys. If the
        // threshold is not equal to the number of subs, the timelock can't be mandatory.
        (false, None)
    }
}

fn random_key(mut seed: u8) -> PublicKey {
    loop {
        let mut data = [0; 65];
        for byte in &mut data[..] {
            *byte = seed;
            // totally a rng
            seed = seed.wrapping_mul(41).wrapping_add(43);
        }
        if data[0] % 2 == 0 {
            data[0] = 4;
            if let Ok(key) = PublicKey::from_slice(&data[..]) {
                return key;
            }
        } else {
            data[0] = 2 + (data[0] >> 7);
            if let Ok(key) = PublicKey::from_slice(&data[..33]) {
                return key;
            }
        }
    }
}

fn is_maybe_liana(raw_script: Vec<u8>) -> bool {
    let script = miniscript::bitcoin::ScriptBuf::from_bytes(raw_script);

    let mut params = ExtParams::new();
    params.raw_pkh = true;
    if let Ok(miniscript) = Miniscript::<
        <miniscript::Segwitv0 as miniscript::ScriptContext>::Key,
        Segwitv0,
    >::parse_with_ext(&script, &params)
    {
        // Miniscript w/ RawPkH cannot be lifted, so we replace all RawPkH by dummy keys
        let mut pkh_map = BTreeMap::new();
        let mut index = 0;
        for ms in miniscript.pre_order_iter() {
            if let Terminal::RawPkH(h) = ms.node {
                let dummy_key = random_key(index);
                index = index.wrapping_add(1);
                pkh_map.insert(h, dummy_key);
            }
        }
        let miniscript = miniscript.substitute_raw_pkh(&pkh_map);

        if let Ok(policy) = miniscript.lift() {
            let policy = policy.normalized();

            let paths = match policy {
                Semantic::Thresh(thresh) if thresh.is_or() && thresh.n() > 1 => thresh.into_data(),
                _ => return false,
            };
            let mut primary_path = None;
            let mut recovery_paths = HashMap::new();

            for p in paths {
                let is_primary_path = is_primary_path(&p);
                let (is_recovery_path, timelock) = is_recovery_path(&p);
                if is_primary_path {
                    if primary_path.is_none() {
                        primary_path = Some(p);
                    } else {
                        // only one non-timelocked path
                        return false;
                    }
                } else if is_recovery_path {
                    let timelock = timelock.unwrap();
                    if let Entry::Vacant(e) = recovery_paths.entry(timelock) {
                        e.insert(p);
                    } else {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            return primary_path.is_some() && !recovery_paths.is_empty();
        }
    }

    false
}

fn main() {
    // let url = "http://127.0.0.1:18443";
    // let auth = Auth::UserPass("pyth".to_string(), "coiner".to_string());

    let url = "http://127.0.0.1:8332";
    let cookie = "/home/pyth/.liana/bitcoind/datadir/.cookie";
    let auth = Auth::CookieFile(cookie.into());

    // let url = "http://127.0.0.1:38332";
    // let cookie = "/home/pyth/.bitcoin/signet/.cookie";
    // let auth = Auth::CookieFile(cookie.into());

    let rpc = Client::new(url, auth).unwrap();
    let mut runner = BlockRunner::new(rpc, 850_500);
    runner.init().unwrap();

    let mut liana_txs = Vec::<(u32, Transaction)>::new();

    loop {
        let block = runner.next();
        let timestamp = block.header.time;
        erase_line();
        println!(
            "processing block {}, {} possible liana tx found",
            runner.fetch_height(),
            liana_txs.len()
        );
        for tx in block.txdata {
            if !tx.is_coinbase()
                && tx.input.iter().any(|inp| {
                    if let Some(script) = inp.witness.last() {
                        if is_maybe_liana(script.to_vec()) {
                            erase_line();
                            println!("{}: {}", timestamp, tx.txid());
                            println!(" ");
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                })
            {
                liana_txs.push((timestamp, tx))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::{Engine as _, BASE64_STANDARD};
    use miniscript::{bitcoin::Psbt, psbt::PsbtExt};

    use crate::is_maybe_liana;

    fn psbt_from_str(s: &str) -> Result<Psbt, String> {
        let data = BASE64_STANDARD.decode(s).unwrap();
        Psbt::deserialize(&data).map_err(|_| "Fail to parse PSBT".to_string())
    }

    #[test]
    fn liana_script() {
        let raw_psbt = "cHNidP8BAF4CAAAAAfELu43G3jXoI6B8vKaH/3/UH+B8rKnM43Hxg+59tC/EAAAAAAD9////Ab1BDwAAAAAAIgAgG7j0pfaGyRIg0MW1tRXIvLmIy1nqd2SqBQnyGsSUl2sAAAAAAAEAzQIAAAAAAQFZErU6gOQL4BklWmuYPHo44bttKgZ7tA/LV2pxRHgq0AAAAAAA/f///wJAQg8AAAAAACIAIHZSW0p69XB3puXgr2PVVi3xS4ic+aX23kZRK3Fe5as05c+aAQAAAAAiUSA8VWmz+5fzAI80yF/wurv28wZ0NQqgzgGB/iRXscn+BQFAk8cp9F5HffcalpWKc+NhNAvmAbENrI4mOj0EIpZiOFpIDnHjPINc494wmWhrM9bMRFAmThv4Ej/Lnyvtyz0lDwAAAAABAStAQg8AAAAAACIAIHZSW0p69XB3puXgr2PVVi3xS4ic+aX23kZRK3Fe5as0IgICPNgm0qQzfdUxkhgD8NazkxcUojDItjkhN7c9HdKH5YtHMEQCIAcu5RkcDUPHagslc2wPp1zVgEwVXd3QHIiaPriJvHhtAiBDQPTLONtdujxJP26G4VFj1L6Z12O3rVtx/Z8o+ZBqJAEiAgMi0FRdsQcbvflX6TiU+085kg021ftDnKHpXoOAdtoZN0cwRAIgJKRrUYX5AkpZ2/dHXSfLZhKgl4J5DbxsxrsL+PPdzUMCIHfTmV9krW0oOumUiUZNgwNX70bwLID9lJXHz6F9BINaAQEFRCEDItBUXbEHG735V+k4lPtPOZINNtX7Q5yh6V6DgHbaGTesc2R2qRQ6Y5OmPxr7xIGw08GuKnsISs8AG4itA///ALJoIgYCPNgm0qQzfdUxkhgD8NazkxcUojDItjkhN7c9HdKH5YsceZVdrTAAAIABAACAAAAAgAIAAIACAAAAAAAAACIGAyLQVF2xBxu9+VfpOJT7TzmSDTbV+0Ocoeleg4B22hk3HHmVXa0wAACAAQAAgAAAAIACAACAAAAAAAAAAAAAIgICAC3kgx/XKEqhBpDOyiQq9N4NVCtzoaHv7krwUMzlUAYceZVdrTAAAIABAACAAAAAgAIAAIADAAAAAAAAACICAzVxiMKfKY24xnU7VGreA2eZ8W9nUBqtsjjeZdeH8/K8HHmVXa0wAACAAQAAgAAAAIACAACAAQAAAAAAAAAA";

        let mut psbt = psbt_from_str(raw_psbt).unwrap();
        let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
        PsbtExt::finalize_mut(&mut psbt, &secp).unwrap();
        let tx = psbt.extract_tx_unchecked_fee_rate();

        // println!("{:#?}", tx);

        // let h = hex::encode(tx.input[0].witness.last().unwrap());
        // println!("{:?}", h);

        // let script = Script::from_bytes(tx.input[0].witness.last().unwrap());
        // println!("{:?}", script);

        // let mut params = ExtParams::new();
        // params.raw_pkh = true;
        // let ms = match miniscript::Miniscript::<
        //     <miniscript::Segwitv0 as miniscript::ScriptContext>::Key,
        //     Segwitv0,
        // >::parse_with_ext(script, &params)
        // {
        //     Ok(ms) => ms,
        //     Err(e) => {
        //         println!("fail to parse miniscript from script: {}", e);
        //         return;
        //     }
        // };

        // println!("miniscript: {:?}", ms);

        let maybe_liana = is_maybe_liana(tx.input[0].witness.last().unwrap().to_vec());
        println!("is_liana: {}", maybe_liana);
    }
}
