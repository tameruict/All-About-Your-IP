// Windows release builds must not open a console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Thin binary entry point. All logic lives in the library crate
//! (`ip_checker_lib`) so it can be unit-tested without a window.

fn main() {
    ip_checker_lib::run()
}
