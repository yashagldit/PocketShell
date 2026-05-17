fn main() {
    println!("cargo:rerun-if-env-changed=POCKETSHELL_DEFAULT_BACKEND_URL");
    println!("cargo:rerun-if-env-changed=POCKETSHELL_DEFAULT_WS_URL");
}
