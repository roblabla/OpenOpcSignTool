//! `hlkx-sign` – sign an HLKX (or VSIX) package with a PKCS#11 module.
//!
//! Usage:
//!   hlkx-sign sign \
//!     --pkcs11-module /usr/lib/opensc-pkcs11.so \
//!     --pkcs11-cert "pkcs11:type=cert;object=MyCert" \
//!     --pkcs11-key  "pkcs11:type=private;object=MyCert" \
//!     [--file-digest sha256] \
//!     [--force] \
//!     package.hlkx

mod c14n;
mod opc;
mod pkcs11;
mod signing;
mod xml_sig;

use clap::{Parser, Subcommand};
use xml_sig::DigestAlgorithm;

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "hlkx-sign", about = "Sign an HLKX/VSIX package with a PKCS#11 module")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign an HLKX/VSIX package.
    Sign {
        /// Path to the PKCS#11 shared library.
        #[arg(long, value_name = "PATH")]
        pkcs11_module: String,

        /// PKCS#11 object identifier for the certificate.
        #[arg(long, value_name = "ID")]
        pkcs11_cert: String,

        /// PKCS#11 object identifier for the private key.
        #[arg(long, value_name = "ID")]
        pkcs11_key: String,

        /// Digest algorithm: sha1 | sha256 | sha384 | sha512 (default: sha256).
        #[arg(long, value_name = "ALGORITHM", default_value = "sha256")]
        file_digest: String,

        /// Overwrite any existing signature.
        #[arg(long, short = 'f')]
        force: bool,

        /// Path to the HLKX/VSIX file to sign.
        file: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry-point
// ─────────────────────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sign {
            pkcs11_module,
            pkcs11_cert,
            pkcs11_key,
            file_digest,
            force,
            file,
        } => {
            let digest_alg = DigestAlgorithm::from_str(&file_digest)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "unsupported digest algorithm '{}'; choose sha1/sha256/sha384/sha512",
                        file_digest
                    )
                })?;

            if !std::path::Path::new(&file).exists() {
                anyhow::bail!("file not found: {}", file);
            }

            eprintln!("Loading certificate from PKCS#11 token...");
            let certificate = pkcs11::load_certificate(&pkcs11_module, &pkcs11_cert)?;

            eprintln!("Loading private key from PKCS#11 token...");
            let private_key = pkcs11::load_private_key(&pkcs11_module, &pkcs11_key)?;

            eprintln!("Opening package: {}", file);
            let mut pkg = opc::OpcPackage::open(&file)?;

            eprintln!("Signing...");
            signing::sign(&mut pkg, &certificate, &private_key, digest_alg, force)?;

            eprintln!("Writing signed package...");
            pkg.save()?;

            eprintln!("Signing complete.");
        }
    }

    Ok(())
}
