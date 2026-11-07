#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // `scrapelens mcp …` is the MCP server (the same code as `scrapelens-mcp`): it runs before
    // Tauri starts, opens no window, and writes only the protocol to stdout.
    if let Some(code) = scrapelens_lib::mcp_subcommand(&args) {
        std::process::exit(code);
    }
    scrapelens_lib::run()
}
