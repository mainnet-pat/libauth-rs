//! Port of `crypto/hash.browser.bench.ts`.
//!
//! libauth bundles `hash.browser.bench.helper.ts` with Rollup and runs it in a
//! headless Chromium page (via Playwright), forwarding the page's console
//! output and `benchError`/`benchComplete` calls. There is no browser here:
//! this benchmark runs the helper's libauth-side measurements natively (see
//! `hash.browser.bench.helper.rs`).

#[path = "hash.browser.bench.helper.rs"]
mod hash_browser_bench_helper;

fn main() {
    // test(`# browser: ${browser.version()}`, ...)
    println!("# browser: none (native run of the browser benchmark's libauth measurements)");
    hash_browser_bench_helper::run();
}
