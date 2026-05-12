//! Load a private key and X.509 certificate from a PKCS#11 token via the
//! OpenSSL `pkcs11` ENGINE.
//!
//! This mirrors the C# code that calls:
//!   ENGINE_by_id("pkcs11")
//!   ENGINE_init
//!   ENGINE_ctrl_cmd_string("MODULE_PATH", module)
//!   ENGINE_load_private_key(engine, key_id)
//!   ENGINE_ctrl_cmd("LOAD_CERT_CTRL", 0, &parms)   → X509*

use anyhow::{bail, Context, Result};
use foreign_types::ForeignType;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr;

// ─────────────────────────────────────────────────────────────────────────────
// Raw OpenSSL ENGINE FFI
// ─────────────────────────────────────────────────────────────────────────────

// Opaque ENGINE type.
#[repr(C)]
struct ENGINE {
    _private: [u8; 0],
}

// UI_METHOD opaque type.
#[repr(C)]
struct UI_METHOD {
    _private: [u8; 0],
}

/// Parameter struct for `LOAD_CERT_CTRL`.
#[repr(C)]
struct LoadCertCtrlArgs {
    id: *const c_char,
    cert: *mut c_void, // X509 *
}

#[link(name = "crypto")]
extern "C" {
    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    fn ENGINE_init(e: *mut ENGINE) -> c_int;
    fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_ctrl_cmd_string(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        arg: *const c_char,
        cmd_optional: c_int,
    ) -> c_int;
    fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const c_char,
        i: c_long,
        p: *mut c_void,
        f: *const c_void,
        cmd_optional: c_int,
    ) -> c_int;
    fn ENGINE_load_private_key(
        e: *mut ENGINE,
        key_id: *const c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut c_void,
    ) -> *mut c_void; // EVP_PKEY *
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Load a private key from a PKCS#11 token via the OpenSSL `pkcs11` engine.
///
/// `module` is the path to the PKCS#11 shared library (e.g.
/// `/usr/lib/opensc-pkcs11.so`).  `key_id` is the PKCS#11 key identifier
/// string (e.g. `"pkcs11:type=private;object=my-key"`).
pub fn load_private_key(module: &str, key_id: &str) -> Result<PKey<Private>> {
    let engine_id = CString::new("pkcs11").unwrap();
    let module_path_cmd = CString::new("MODULE_PATH").unwrap();
    let module_c = CString::new(module).context("module path contains NUL byte")?;
    let key_id_c = CString::new(key_id).context("key_id contains NUL byte")?;

    unsafe {
        let engine = ENGINE_by_id(engine_id.as_ptr());
        if engine.is_null() {
            bail!("ENGINE_by_id(\"pkcs11\") failed – is libengine-pkcs11-openssl installed?");
        }

        // Set module path before init so the engine knows which PKCS#11 library
        // to load.  `cmd_optional = 1` means: do not error if the command is
        // not supported before init.
        ENGINE_ctrl_cmd_string(engine, module_path_cmd.as_ptr(), module_c.as_ptr(), 1);

        if ENGINE_init(engine) == 0 {
            ENGINE_free(engine);
            bail!("ENGINE_init failed for pkcs11 engine");
        }

        // Also set MODULE_PATH after init (some engine versions require this).
        ENGINE_ctrl_cmd_string(engine, module_path_cmd.as_ptr(), module_c.as_ptr(), 0);

        let evp_pkey =
            ENGINE_load_private_key(engine, key_id_c.as_ptr(), ptr::null_mut(), ptr::null_mut());

        ENGINE_finish(engine);
        ENGINE_free(engine);

        if evp_pkey.is_null() {
            bail!("ENGINE_load_private_key failed – check key_id \"{}\"", key_id);
        }

        // Wrap the raw EVP_PKEY* in an openssl PKey.
        // Safety: `evp_pkey` is a valid, owned EVP_PKEY* returned by OpenSSL.
        let pkey = PKey::from_ptr(evp_pkey as *mut _);
        Ok(pkey)
    }
}

/// Load an X.509 certificate from a PKCS#11 token via the OpenSSL `pkcs11`
/// engine using the `LOAD_CERT_CTRL` control command.
pub fn load_certificate(module: &str, cert_id: &str) -> Result<X509> {
    let engine_id = CString::new("pkcs11").unwrap();
    let module_path_cmd = CString::new("MODULE_PATH").unwrap();
    let load_cert_ctrl = CString::new("LOAD_CERT_CTRL").unwrap();
    let module_c = CString::new(module).context("module path contains NUL byte")?;
    let cert_id_c = CString::new(cert_id).context("cert_id contains NUL byte")?;

    unsafe {
        let engine = ENGINE_by_id(engine_id.as_ptr());
        if engine.is_null() {
            bail!("ENGINE_by_id(\"pkcs11\") failed – is libengine-pkcs11-openssl installed?");
        }

        ENGINE_ctrl_cmd_string(engine, module_path_cmd.as_ptr(), module_c.as_ptr(), 1);

        if ENGINE_init(engine) == 0 {
            ENGINE_free(engine);
            bail!("ENGINE_init failed for pkcs11 engine");
        }

        ENGINE_ctrl_cmd_string(engine, module_path_cmd.as_ptr(), module_c.as_ptr(), 0);

        let mut args = LoadCertCtrlArgs {
            id: cert_id_c.as_ptr(),
            cert: ptr::null_mut(),
        };

        let rc = ENGINE_ctrl_cmd(
            engine,
            load_cert_ctrl.as_ptr(),
            0,
            &mut args as *mut _ as *mut c_void,
            ptr::null(),
            1,
        );

        ENGINE_finish(engine);
        ENGINE_free(engine);

        if rc == 0 || args.cert.is_null() {
            bail!("LOAD_CERT_CTRL failed – check cert_id \"{}\"", cert_id);
        }

        // Wrap the raw X509* in an openssl X509.
        // Safety: `args.cert` is a valid, owned X509* returned by OpenSSL.
        let x509 = X509::from_ptr(args.cert as *mut _);
        Ok(x509)
    }
}
