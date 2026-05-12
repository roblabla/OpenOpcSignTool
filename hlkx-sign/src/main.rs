//! `hlkx-sign` – sign an HLKX (or VSIX) package with a PKCS#11 module.
//!
//! Usage:
//!   hlkx-sign sign \
//!     --pkcs11-module /usr/lib/opensc-pkcs11.so \
//!     --pkcs11-cert "pkcs11:type=cert;object=MyCert" \
//!     --pkcs11-key  "pkcs11:type=private;object=MyCert" \
//!     [--pkcs11-pin 1234] \
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

        /// PKCS#11 URI or object label for the certificate.
        #[arg(long, value_name = "ID")]
        pkcs11_cert: String,

        /// PKCS#11 URI or object label for the private key.
        #[arg(long, value_name = "ID")]
        pkcs11_key: String,

        /// Optional user PIN for the PKCS#11 token.
        #[arg(long, value_name = "PIN")]
        pkcs11_pin: Option<String>,

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
            pkcs11_pin,
            file_digest,
            force,
            file,
        } => {
            let digest_alg = DigestAlgorithm::from_str(&file_digest).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported digest algorithm '{}'; choose sha1/sha256/sha384/sha512",
                    file_digest
                )
            })?;

            if !std::path::Path::new(&file).exists() {
                anyhow::bail!("file not found: {}", file);
            }

            let pin = pkcs11_pin.as_deref();

            eprintln!("Loading certificate from PKCS#11 token...");
            let cert_der =
                pkcs11::load_certificate_der(&pkcs11_module, &pkcs11_cert, pin)?;

            // Build a signing closure that will be called once (to sign SignedInfo).
            let signer = {
                let module = pkcs11_module.clone();
                let key = pkcs11_key.clone();
                let pin_owned = pkcs11_pin.clone();
                move |data: &[u8]| {
                    pkcs11::pkcs11_sign(
                        &module,
                        &key,
                        digest_alg,
                        pin_owned.as_deref(),
                        data,
                    )
                }
            };

            eprintln!("Opening package: {}", file);
            let mut pkg = opc::OpcPackage::open(&file)?;

            eprintln!("Signing...");
            signing::sign(&mut pkg, &cert_der, &signer, digest_alg, force)?;

            eprintln!("Writing signed package...");
            pkg.save()?;

            eprintln!("Signing complete.");
        }
    }

    Ok(())
}
