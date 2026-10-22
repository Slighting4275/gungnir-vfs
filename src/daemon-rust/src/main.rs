use std::{env, path::PathBuf, process::ExitCode};

use gungnird::{Error, Result, open_db};

fn db_path() -> Result<PathBuf> {
    if let Some(arg) = env::args_os().nth(1) {
        return Ok(PathBuf::from(arg));
    }
    // An empty HOME would yield a relative path and put the DB under the CWD.
    let home = env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or(Error::NoHome)?;
    Ok(PathBuf::from(home).join(".cache/gungnir/metadata.db"))
}

fn run() -> Result<()> {
    let path = db_path()?;
    let _conn = open_db(&path)?;
    eprintln!("gungnird: metadata db ready at {}", path.display());
    Ok(())
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
