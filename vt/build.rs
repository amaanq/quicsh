//! Compiles the C side of the bindings against the installed libghostty-vt
//! and links the library statically.

use std::{
   env,
   process::Command,
};

/// A variable of the library's pkg-config file.
fn variable(name: &str) -> String {
   let output = Command::new(env::var("PKG_CONFIG").unwrap_or_else(|_| "pkg-config".to_owned()))
      .arg(format!("--variable={name}"))
      .arg("libghostty-vt-static")
      .output()
      .expect("pkg-config runs");

   assert!(
      output.status.success(),
      "pkg-config finds no libghostty-vt-static, is it on PKG_CONFIG_PATH?"
   );

   String::from_utf8(output.stdout)
      .expect("pkg-config prints a path")
      .trim()
      .to_owned()
}

fn main() {
   println!("cargo:rerun-if-changed=src/shim.c");
   println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

   cc::Build::new()
      .file("src/shim.c")
      .include(variable("includedir"))
      // The nix compiler wrapper defines _FORTIFY_SOURCE, and glibc warns
      // about that without optimization, which a debug build has none of.
      .opt_level(2)
      .warnings_into_errors(true)
      .compile("quicsh-vt-shim");

   println!("cargo:rustc-link-search=native={}", variable("libdir"));
   println!("cargo:rustc-link-lib=static=ghostty-vt");
}
