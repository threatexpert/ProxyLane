use proxylane_mitm::{
    pki::{directory, Authority},
    windows,
};

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let action = args.first().map(String::as_str).unwrap_or("status");
    if !["init", "status", "install", "remove"].contains(&action) {
        return Err("Usage: proxylane-mitm [init|status|install|remove]\nCurrentUser ROOT only. PROXYLANE_MITM_HOME overrides the data directory.".into());
    }
    let ca = Authority::load(&directory()?, action == "init" || action == "install")?;
    let trusted = windows::trust(&ca.der, if action == "init" { "status" } else { action })?;
    println!(
        "{}",
        serde_json::json!({"action":action, "sha256":ca.id, "trusted_current_user":trusted,
        "certificate":ca.directory.join("proxylane-ca.cer"), "crl_port":ca.port})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
