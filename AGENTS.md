# citodin

3DS ROM decrypter. Odin + Dear ImGui + SDL3 + OpenGL 3.3.
Port of [citrust](https://github.com/londospark/citrust) from Rust.

## Project structure

- `main.odin` — entry point, GUI loop
- `gui.odin` — GUI screens (KeySetup, SelectFile, Decrypting, Done)
- `keys.odin` — CryptoMethod enum
- `crypto.odin` — AES-CTR wrapper, 3DS key derivation
- `keydb.odin` — KeyDatabase (parse/save/search aes_keys.txt)
- `ncsd.odin` — NCSD header parsing
- `ncch.odin` — NCCH header parsing
- `decrypt.odin` — decrypt_rom orchestrator
- `vendor/imgui/` — Dear ImGui + SDL3 + OpenGL3 backends via dcimgui C wrapper
- `vendor/sdl3_headers/` — SDL3 C headers for backend compilation
- `vendor/gl/` — OpenGL 3.3 core bindings
- `_compile_libs.sh` — compiles ImGui C++ sources into static lib
- `Roboto.ttf` — UI font
- `build.sh` — Unix build script
- `build.bat` — Windows build script

## Build

**First build** (compiles vendor C++ libs, then Odin):
```
./build.sh [run|release|clean]
```

**Subsequent builds** (Odin-only, fast):
```
odin build . -vet -out:bin/citodin
odin run . -vet
odin check .
odin test .
```

`./build.sh run` builds and launches.
`./build.sh release` adds `-o:speed`.
`./build.sh clean` removes `bin/` and `build/`.

## Phases

- Phase 0: Project scaffolding ✅
- Phase 1: Core types & crypto (keys.odin, crypto.odin)
- Phase 2: Key database (keydb.odin)
- Phase 3: Header parsing (ncsd.odin, ncch.odin)
- Phase 4: Decryption orchestrator (decrypt.odin)
- Phase 5: GUI (gui.odin)
- Phase 6: Polish & cross-platform

## Key design decisions

- All source in `package main` across multiple files (standard Odin convention)
- Uses Odin's `core:crypto/aes` for AES-CTR (hardware-accelerated on x86_64)
- Uses Odin's `core:mem/virtual` for memory-mapped file I/O
- Threading via `core:thread` for parallel CTR decryption
- Progress via mutex-guarded shared state (no channels needed)
- SDL3 for window + input, OpenGL 3.3 core for rendering
- ImGui backends: SDL3 platform + OpenGL3 renderer (standard Dear ImGui backends)
- Catppuccin dark theme
- Docking via `DockSpaceOverViewport` + `io.ConfigFlags |= {.DockingEnable}`
- Uncapped frame loop with sleep-based pacing + adaptive throttle

## Porting notes

- `vendor:sdl3` resolves to Odin's built-in SDL3 bindings
- `vendor/imgui` resolves to local `vendor/imgui/` (not a built-in collection — use slash)
- ImGui bindings via dcimgui C wrapper: `ImGui_` prefix for bare functions, `Im` for namespaced
- Foreign lib blocks in imgui.odin: all backends link against the same `imgui.a`
