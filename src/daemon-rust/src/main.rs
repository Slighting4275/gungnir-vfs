use std::{env, path::PathBuf, process::ExitCode, sync::Arc};

use gungnird::{
    Result,
    fsid::{Resolver, ResolverConfig, SysBackend},
    ipc, mdsvc,
    store::{self, DbConfig, Store, StoreConfig},
};

/// The first CLI argument, else `$XDG_DATA_HOME/gungnir/metadata.db`, else
/// `$HOME/.local/share/gungnir/metadata.db`.
fn db_path() -> Result<PathBuf> {
    if let Some(arg) = env::args_os().nth(1) {
        return Ok(PathBuf::from(arg));
    }
    store::default_db_path(
        env::var_os("XDG_DATA_HOME").as_deref(),
        env::var_os("HOME").as_deref(),
    )
}

fn run() -> Result<()> {
    let path = db_path()?;
    let db = store::spawn(
        Store::open(&path, StoreConfig::default())?,
        DbConfig::default(),
    )?;
    eprintln!("gungnird: metadata db ready at {}", path.display());
    let resolver = Arc::new(Resolver::new(
        SysBackend::new()?,
        ResolverConfig::default(),
    )?);
    let handler: Arc<dyn ipc::Handler> = Arc::new(mdsvc::Service::new(resolver, db));
    let sock = ipc::socket_path_from_env()?;
    let listener = ipc::bind(&sock)?;
    eprintln!("gungnird: listening on {}", sock.display());
    ipc::serve(&listener.socket, ipc::Config::default(), &handler)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gungnird: {e}");
            ExitCode::FAILURE
        }
    }
}
