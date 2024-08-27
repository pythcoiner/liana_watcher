use bitcoincore_rpc::Auth;
use clap::Parser;

#[derive(Parser, Debug)]
pub struct Cli {
    /// ip:port url of bitcoind
    #[arg(short, long)]
    pub ip: String,
    /// cookie file path
    #[arg(short, long)]
    cookie: Option<String>,
    /// user for bitcoind auth
    #[arg(short, long)]
    user: Option<String>,
    /// password for bitcoind auth
    #[arg(short, long)]
    password: Option<String>,
    /// start block height
    #[arg(short, long)]
    start: Option<u64>,
}

impl Cli {
    pub fn auth(&self) -> Result<Auth, String> {
        match (&self.cookie, &self.user, &self.password) {
            (Some(cookie), None, None) => Ok(Auth::CookieFile(cookie.into())),
            (None, Some(user), Some(password)) => Ok(Auth::UserPass(user.into(), password.into())),
            _ => Err(
                "Wrong auth data, you sould supply a cookie path OR a pair user/password!".into(),
            ),
        }
    }

    pub fn start(&self) -> u64 {
        self.start.unwrap_or(1)
    }
}
