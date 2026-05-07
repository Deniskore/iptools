# WASM Support

The core `iptools` crate stays focused on Rust APIs and can be checked for
`wasm32-unknown-unknown`. Browser-facing `wasm-bindgen` bindings live in
`crates/iptools-wasm` for the repository demo and are generated with
`wasm-pack`.

The `iptools-wasm` crate is not published separately. Clone this repository when
you want to build the demo bindings.

## Prerequisites

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
cargo install basic-http-server
```

## Build

From the repository root:

```bash
cd crates/iptools-wasm
wasm-pack build --target web --out-dir ../../examples/pkg --out-name iptools
```

This writes the browser package expected by the demo:

```text
examples/pkg/iptools.js
examples/pkg/iptools_bg.wasm
```

## Run the Demo

Serve the `examples` directory over HTTP:

```bash
basic-http-server examples -a 127.0.0.1:8000
```

Then open:

```text
http://127.0.0.1:8000/wasm_demo.html
```

The demo imports `./pkg/iptools.js`, so rebuild the WASM package after changing
the bindings or core APIs. Opening the HTML file directly from disk may fail
because browsers restrict ES module and WASM loading from `file://` URLs.
