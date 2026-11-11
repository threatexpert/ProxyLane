use std::{io, ptr, slice};
use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
use zeroize::Zeroize;

pub fn protect(input: &[u8], decrypt: bool) -> Result<Vec<u8>, String> {
    let data = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &data,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptProtectData(
                &data,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if ok == 0 {
        return Err(format!("DPAPI: {}", io::Error::last_os_error()));
    }
    unsafe {
        let bytes = slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let result = bytes.to_vec();
        bytes.zeroize();
        LocalFree(out.pbData as _);
        Ok(result)
    }
}

// Only the exact public certificate in CurrentUser\ROOT is installed/removed.
pub fn trust(der: &[u8], action: &str) -> Result<bool, String> {
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER
                | if action == "status" {
                    CERT_STORE_READONLY_FLAG
                } else {
                    0
                },
            [82u16, 79, 79, 84, 0].as_ptr() as _,
        );
        if store.is_null() {
            return Err(io::Error::last_os_error().to_string());
        }
        let result = (|| {
            let mut context = CertEnumCertificatesInStore(store, ptr::null());
            let mut found = false;
            while !context.is_null() {
                let value = &*context;
                if slice::from_raw_parts(value.pbCertEncoded, value.cbCertEncoded as usize) == der {
                    found = true;
                    if action == "remove" {
                        let copy = CertDuplicateCertificateContext(context);
                        if CertDeleteCertificateFromStore(copy) == 0 {
                            CertFreeCertificateContext(context);
                            return Err(io::Error::last_os_error().to_string());
                        }
                    }
                }
                context = CertEnumCertificatesInStore(store, context);
            }
            if action == "install"
                && !found
                && CertAddEncodedCertificateToStore(
                    store,
                    X509_ASN_ENCODING,
                    der.as_ptr(),
                    der.len() as u32,
                    CERT_STORE_ADD_NEW,
                    ptr::null_mut(),
                ) == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            Ok(if action == "remove" {
                false
            } else {
                found || action == "install"
            })
        })();
        CertCloseStore(store, 0);
        result
    }
}
