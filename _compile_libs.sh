#!/bin/sh
set -e

: "${CC:=}"
: "${CXX:=}"
: "${AR:=ar}"

detect_cc() {
    if [ -n "$CC" ]; then
        return 0
    fi
    for c in gcc clang cc; do
        if command -v "$c" >/dev/null 2>&1; then
            CC="$c"
            return 0
        fi
    done
    echo "Error: C compiler not found."
    exit 1
}

detect_cxx() {
    if [ -n "$CXX" ]; then
        return 0
    fi
    for c in g++ clang++ c++; do
        if command -v "$c" >/dev/null 2>&1; then
            CXX="$c"
            return 0
        fi
    done
    echo "Error: C++ compiler not found."
    exit 1
}

ensure_imgui() {
    if [ -f vendor/imgui/imgui.a ]; then
        return 0
    fi

    detect_cxx

    echo "Compiling ImGui + backends from source..."

    IMGUI=vendor/imgui
    SDL3INC=vendor/sdl3_headers

    CFLAGS="-std=c++17 -O2 -DIMGUI_ENABLE_DOCKING -DIMGUI_IMPL_API="
    INC="-I$IMGUI -I$IMGUI/backends -I$SDL3INC"

    $CXX -c $CFLAGS $INC \
        "$IMGUI/imgui.cpp" \
        "$IMGUI/imgui_draw.cpp" \
        "$IMGUI/imgui_tables.cpp" \
        "$IMGUI/imgui_widgets.cpp" \
        "$IMGUI/imgui_demo.cpp" \
        "$IMGUI/dcimgui.cpp" \
        "$IMGUI/backends/imgui_impl_sdl3.cpp" \
        "$IMGUI/backends/imgui_impl_opengl3.cpp"

    $AR rcs "$IMGUI/imgui.a" *.o
    rm -f *.o
}

ensure_imgui
