# WASM Support

## Quick Start

### Prerequisites:

```bash
# Install wasm32 target
rustup target add wasm32-unknown-unknown

# Install wasm-pack (WASM build tool)
cargo install wasm-pack

# Install basic-http-server (for testing)
cargo install basic-http-server
```

### Building for WASM:

```bash
# Build for web browsers
wasm-pack build --target web --out-dir examples/pkg
```

### Testing Locally:
```bash
# Start HTTP server in the examples directory
basic-http-server examples -a 127.0.0.1:8000

# Open in browser
# http://127.0.0.1:8000/wasm_demo.html
```
