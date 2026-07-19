package main

import "core:fmt"
import "core:time"
import sdl "vendor:sdl3"
import ig "vendor/imgui"
import sdl_impl "vendor/imgui/backends"
import gl_impl "vendor/imgui/backends/opengl3"

WINDOW_TITLE :: "citodin — 3DS ROM Decrypter"
WINDOW_WIDTH  :: 1280
WINDOW_HEIGHT :: 800
FPS_CEILING   :: 240.0

main :: proc() {
	sdl.SetHint("SDL_HINT_IME_SHOW_UI", "1")

	if !sdl.Init({.VIDEO}) {
		fmt.eprintfln("SDL3 init failed: %s", sdl.GetError())
		return
	}
	defer sdl.Quit()

	sdl.GL_SetAttribute(.CONTEXT_MAJOR_VERSION, 3)
	sdl.GL_SetAttribute(.CONTEXT_MINOR_VERSION, 3)
	sdl.GL_SetAttribute(.CONTEXT_PROFILE_MASK, i32(sdl.GL_CONTEXT_PROFILE_CORE))

	window := sdl.CreateWindow(WINDOW_TITLE, WINDOW_WIDTH, WINDOW_HEIGHT, {.OPENGL, .HIGH_PIXEL_DENSITY, .RESIZABLE})
	if window == nil {
		fmt.eprintfln("SDL3 CreateWindow failed: %s", sdl.GetError())
		return
	}
	defer sdl.DestroyWindow(window)

	gl_context := sdl.GL_CreateContext(window)
	if gl_context == nil {
		fmt.eprintfln("SDL3 GL context failed: %s", sdl.GetError())
		return
	}
	defer sdl.GL_DestroyContext(gl_context)

	sdl.GL_MakeCurrent(window, gl_context)
	sdl.GL_SetSwapInterval(0)

	ig.CreateContext()
	defer ig.DestroyContext(nil)
	set_theme()

	io := ig.GetIO()
	font_filename :: "Roboto.ttf"
	ascii_range := [?]ig.Wchar{32, 126, 0}
	ig.FontAtlas_AddFontFromFileTTF(io.Fonts, font_filename, glyph_ranges = &ascii_range[0])

	if !sdl_impl.InitForOpenGL(window, gl_context) {
		fmt.eprintln("ImGui SDL3 backend init failed")
		return
	}
	defer sdl_impl.Shutdown()

	if !gl_impl.Init("#version 330 core") {
		fmt.eprintln("ImGui OpenGL3 backend init failed")
		return
	}
	defer gl_impl.Shutdown()

	display_id := sdl.GetDisplayForWindow(window)
	mode := sdl.GetCurrentDisplayMode(display_id)
	refresh_rate := f64(max(mode.refresh_rate, 60.0))

	multiple: u32 = 1
	fps_target: f64 = refresh_rate
	frame_time_target: f64 = 1.0 / refresh_rate

	{
		m := clamp(u32(FPS_CEILING / refresh_rate), 1, 4)
		t := min(refresh_rate * f64(m), FPS_CEILING)
		fps_target = t
		frame_time_target = 1.0 / t
		multiple = m
	}

	FPS_HISTORY :: 30
	fps_ring: [FPS_HISTORY]f64
	fps_idx: u32
	fps_full := false

	event: sdl.Event
	running := true
	io.ConfigFlags += {.DockingEnable}
	t0 := time.tick_now()

	for running {
		for sdl.PollEvent(&event) {
			if event.type == .QUIT { running = false }
			sdl_impl.ProcessEvent(&event)
		}

		{
			mx, my: f32
			_ = sdl.GetMouseState(&mx, &my)
			io.MousePos = ig.Vec2{mx, my}
		}

		gl_impl.NewFrame()
		sdl_impl.NewFrame()
		ig.NewFrame()
		ig.DockSpaceOverViewport(viewport = ig.GetMainViewport())

		ig.ShowDemoWindow(nil)

		ig.Render()
		gl_impl.RenderDrawData(ig.GetDrawData())
		sdl.GL_SwapWindow(window)

		elapsed := time.duration_seconds(time.tick_since(t0))
		if elapsed < frame_time_target {
			remaining := frame_time_target - elapsed
			time.sleep(time.Duration(1e9 * remaining))
		}

		{
			actual := 1.0 / max(elapsed, 1e-9)
			fps_ring[fps_idx] = actual
			fps_idx = (fps_idx + 1) % FPS_HISTORY
			if fps_idx == 0 { fps_full = true }

			if fps_full && multiple > 1 {
				avg := 0.0
				for v in fps_ring { avg += v }
				avg /= FPS_HISTORY
				THROTTLE_RATIO :: 0.8
				if avg < fps_target * THROTTLE_RATIO {
					multiple -= 1
					t := min(refresh_rate * f64(multiple), FPS_CEILING)
					fps_target = t
					frame_time_target = 1.0 / t
					fps_full = false
				}
			}
		}

		t0 = time.tick_now()
	}
}

rgba :: proc(r, g, b: u8, a: f32 = 1.0) -> ig.Vec4 {
	return {f32(r) / 255.0, f32(g) / 255.0, f32(b) / 255.0, a}
}

set_theme :: proc() {
	style := ig.GetStyle()

	style.WindowRounding = 4.0
	style.FrameRounding = 3.0
	style.PopupRounding = 4.0
	style.ScrollbarRounding = 3.0
	style.GrabRounding = 3.0
	style.TabRounding = 3.0
	style.ChildRounding = 4.0

	style.WindowBorderSize = 1.0
	style.FrameBorderSize = 0.0
	style.PopupBorderSize = 1.0
	style.ChildBorderSize = 1.0

	style.WindowPadding = {10.0, 10.0}
	style.FramePadding = {8.0, 4.0}
	style.ItemSpacing = {8.0, 5.0}
	style.ItemInnerSpacing = {5.0, 5.0}
	style.IndentSpacing = 18.0
	style.ScrollbarSize = 12.0
	style.GrabMinSize = 10.0
	style.WindowMinSize = {60.0, 60.0}

	style.Colors[ig.Col.Text]              = rgba(205, 214, 244)
	style.Colors[ig.Col.TextDisabled]      = rgba(127, 132, 156)
	style.Colors[ig.Col.WindowBg]          = rgba(24,  25,  38)
	style.Colors[ig.Col.ChildBg]           = rgba(20,  21,  33)
	style.Colors[ig.Col.PopupBg]           = rgba(31,  33,  48)
	style.Colors[ig.Col.Border]            = rgba(60,  63,  85)
	style.Colors[ig.Col.BorderShadow]      = rgba(0,    0,   0, 0)
	style.Colors[ig.Col.FrameBg]           = rgba(40,  42,  60)
	style.Colors[ig.Col.FrameBgHovered]    = rgba(54,  56,  78)
	style.Colors[ig.Col.FrameBgActive]     = rgba(68,  71,  97)
	style.Colors[ig.Col.TitleBg]           = rgba(20,  21,  33)
	style.Colors[ig.Col.TitleBgActive]     = rgba(35,  37,  54)
	style.Colors[ig.Col.TitleBgCollapsed]  = rgba(20,  21,  33)
	style.Colors[ig.Col.MenuBarBg]         = rgba(31,  33,  48)
	style.Colors[ig.Col.ScrollbarBg]       = rgba(24,  25,  38)
	style.Colors[ig.Col.ScrollbarGrab]     = rgba(60,  63,  85)
	style.Colors[ig.Col.ScrollbarGrabHovered] = rgba(81,  85, 111)
	style.Colors[ig.Col.ScrollbarGrabActive]  = rgba(104, 108, 138)
	style.Colors[ig.Col.CheckMark]         = rgba(137, 180, 250)
	style.Colors[ig.Col.SliderGrab]        = rgba(137, 180, 250)
	style.Colors[ig.Col.SliderGrabActive]  = rgba(159, 194, 252)
	style.Colors[ig.Col.Button]            = rgba(45,  47,  66)
	style.Colors[ig.Col.ButtonHovered]     = rgba(59,  62,  86)
	style.Colors[ig.Col.ButtonActive]      = rgba(74,  78, 107)
	style.Colors[ig.Col.Header]            = rgba(45,  47,  66)
	style.Colors[ig.Col.HeaderHovered]     = rgba(59,  62,  86)
	style.Colors[ig.Col.HeaderActive]      = rgba(74,  78, 107)
	style.Colors[ig.Col.Separator]         = rgba(60,  63,  85)
	style.Colors[ig.Col.SeparatorHovered]  = rgba(137, 180, 250)
	style.Colors[ig.Col.SeparatorActive]   = rgba(159, 194, 252)
	style.Colors[ig.Col.ResizeGrip]        = rgba(60,  63,  85)
	style.Colors[ig.Col.ResizeGripHovered] = rgba(137, 180, 250)
	style.Colors[ig.Col.ResizeGripActive]  = rgba(159, 194, 252)
	style.Colors[ig.Col.Tab]               = rgba(31,  33,  48)
	style.Colors[ig.Col.TabHovered]        = rgba(54,  56,  78)
	style.Colors[ig.Col.TabSelected]       = rgba(45,  47,  66)
	style.Colors[ig.Col.TabDimmed]         = rgba(24,  25,  38)
	style.Colors[ig.Col.TabDimmedSelected] = rgba(35,  37,  54)
	style.Colors[ig.Col.DockingPreview]    = rgba(137, 180, 250, 0.30)
	style.Colors[ig.Col.DockingEmptyBg]    = rgba(20,  21,  33)
	style.Colors[ig.Col.TextLink]          = rgba(137, 180, 250)
	style.Colors[ig.Col.TextSelectedBg]    = rgba(137, 180, 250, 0.25)
	style.Colors[ig.Col.DragDropTarget]    = rgba(137, 180, 250, 0.80)
	style.Colors[ig.Col.DragDropTargetBg]  = rgba(137, 180, 250, 0.15)
	style.Colors[ig.Col.NavCursor]         = rgba(137, 180, 250)
	style.Colors[ig.Col.ModalWindowDimBg]  = rgba(0,    0,   0, 0.50)
}
