package main

import "base:runtime"
import "core:c"
import "core:fmt"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import sdl "vendor:sdl3"
import ig "vendor/imgui"

Screen :: enum {
	KeySetup,
	SelectFile,
	Decrypting,
	Done,
}

ProgressState :: struct {
	lock:              sync.Mutex,
	messages:          [dynamic]string,
	current_section:   string,
	encryption_method: string,
	start_time:        time.Time,
	done:              bool,
	had_error:         bool,
}

CitrustApp :: struct {
	screen:           Screen,
	selected_file:    string,
	window:           ^sdl.Window,
	keydb:            KeyDatabase,
	keydb_loaded:     bool,
	key_status:       string,
	key_save_message: string,
	progress:         ProgressState,
	font_large:       ^ig.Font,
	font_body:        ^ig.Font,
	font_button:      ^ig.Font,
	font_small:       ^ig.Font,
}

citrust_app_init :: proc(app: ^CitrustApp, window: ^sdl.Window) {
	app.window = window
	app.screen = .KeySetup

	if path, found := keydb_search_default_locations(); found {
		if db, err := keydb_from_file(path); err == nil {
			app.keydb = db
			app.keydb_loaded = true
			app.key_status = fmt.tprintf("🔑 Keys loaded (%d keys)", keydb_len(&db))
			app.screen = .SelectFile
		}
	}

	io := ig.GetIO()
	app.font_large  = ig.FontAtlas_AddFontFromFileTTF(io.Fonts, "Roboto.ttf", 48)
	app.font_body   = ig.FontAtlas_AddFontFromFileTTF(io.Fonts, "Roboto.ttf", 24)
	app.font_button = ig.FontAtlas_AddFontFromFileTTF(io.Fonts, "Roboto.ttf", 28)
	app.font_small  = ig.FontAtlas_AddFontFromFileTTF(io.Fonts, "Roboto.ttf", 16)
}

citrust_app_destroy :: proc(app: ^CitrustApp) {
	if app.keydb_loaded {
		keydb_destroy(&app.keydb)
	}
}

citrust_app_update :: proc(app: ^CitrustApp) {
	display := ig.GetIO().DisplaySize
	ig.SetNextWindowPos({0, 0}, .Always)
	ig.SetNextWindowSize(display, .Always)
	ig.PushStyleVarX(.WindowPadding, 0)
	ig.PushStyleVarY(.WindowPadding, 0)
	ig.PushStyleVarX(.FramePadding, 16)
	ig.PushStyleVarY(.FramePadding, 8)
	ig.PushStyleVarX(.ItemSpacing, 0)
	ig.PushStyleVarY(.ItemSpacing, 12)

	if ig.Begin("##citodin_main", nil, {.NoTitleBar, .NoResize, .NoMove, .NoScrollbar, .NoSavedSettings, .MenuBar}) {
		ig.PushStyleColor(.ChildBg, ig.ColorConvertFloat4ToU32({0.09, 0.10, 0.15, 1.0}))
		ig.BeginChild("##content", {display.x, display.y - 36}, {.AlwaysUseWindowPadding})
		ig.SetCursorPosY(display.y * 0.15)

		switch app.screen {
		case .KeySetup:
			app_show_key_setup_screen(app)
		case .SelectFile:
			app_show_select_file_screen(app)
		case .Decrypting:
			app_show_decrypting_screen(app)
		case .Done:
			app_show_done_screen(app)
		}

		ig.EndChild()
		ig.PopStyleColor()

		ig.Separator()
		app_show_key_footer(app)
		ig.End()
	}

	ig.PopStyleVar(6)
}

app_show_key_footer :: proc(app: ^CitrustApp) {
	if !app.keydb_loaded { return }

	ig.PushFontFloat(app.font_small, app.font_small.LegacySize)
	status_cstr := strings.clone_to_cstring(app.key_status, context.temp_allocator)
	ig.Text(status_cstr)
	ig.SameLine()
	ig.SetCursorPosX(ig.GetIO().DisplaySize.x - 100)
	if ig.Button("Browse…") {
		filters := [?]sdl.DialogFileFilter{{"Key File", "txt"}}
		sdl.ShowOpenFileDialog(proc "c" (userdata: rawptr, filelist: [^]cstring, filter: c.int) {
			context = runtime.default_context()
			app := (^CitrustApp)(userdata)
			if filelist != nil && filelist[0] != nil {
				path := string(filelist[0])
				if db, err := keydb_from_file(path); err == nil {
					save_path, _ := keydb_default_save_path()
					if save_path != "" {
						keydb_save_to_file(&db, save_path)
					}
					app.keydb = db
					app.keydb_loaded = true
					app.key_status = fmt.tprintf("🔑 Keys loaded (%d keys)", keydb_len(&db))
					if app.screen == .KeySetup {
						app.screen = .SelectFile
					}
				} else {
					app.key_save_message = "❌ Invalid key file"
				}
			}
		}, app, app.window, &filters[0], 1, nil, false)
	}
	ig.PopFont()
}

app_toast :: proc(app: ^CitrustApp) {
	if app.key_save_message == "" { return }
	is_error := strings.has_prefix(app.key_save_message, "❌")

	if is_error {
		ig.PushStyleColor(.Text, ig.ColorConvertFloat4ToU32({0.86, 0.31, 0.31, 1.0}))
	} else {
		ig.PushStyleColor(.Text, ig.ColorConvertFloat4ToU32({0.39, 0.78, 0.39, 1.0}))
	}
	ig.PushFontFloat(app.font_body, app.font_body.LegacySize)
	msg_cstr := strings.clone_to_cstring(app.key_save_message, context.temp_allocator)
	ig.Text(msg_cstr)
	ig.PopFont()
	ig.PopStyleColor()
}

app_show_key_setup_screen :: proc(app: ^CitrustApp) {
	ig.PushFontFloat(app.font_large, app.font_large.LegacySize)
	ig.Text("🔑 Key Setup Required")
	ig.PopFont()
	ig.Dummy({0, 20})

	ig.PushFontFloat(app.font_body, app.font_body.LegacySize)
	ig.Text("citodin needs an aes_keys.txt file to decrypt 3DS ROMs.")
	ig.Dummy({0, 30})
	ig.PopFont()

	ig.PushFontFloat(app.font_button, app.font_button.LegacySize)
	if ig.Button("📁 Browse for Key File", {400, 80}) {
		filters := [?]sdl.DialogFileFilter{{"Key File", "txt"}}
		sdl.ShowOpenFileDialog(proc "c" (userdata: rawptr, filelist: [^]cstring, filter: c.int) {
			context = runtime.default_context()
			app := (^CitrustApp)(userdata)
			if filelist != nil && filelist[0] != nil {
				path := string(filelist[0])
				if db, err := keydb_from_file(path); err == nil {
					save_path, _ := keydb_default_save_path()
					if save_path != "" {
						keydb_save_to_file(&db, save_path)
					}
					app.keydb = db
					app.keydb_loaded = true
					app.key_status = fmt.tprintf("🔑 Keys loaded (%d keys)", keydb_len(&db))
					app.key_save_message = "✅ Keys saved — you won't need to do this again"
					app.screen = .SelectFile
				} else {
					app.key_save_message = "❌ Invalid key file"
				}
			}
		}, app, app.window, &filters[0], 1, nil, false)
	}
	ig.PopFont()
	ig.Dummy({0, 10})

	app_toast(app)

	ig.Dummy({0, 20})
	ig.PushFontFloat(app.font_small, app.font_small.LegacySize)
	ig.TextDisabled("You can dump keys from your 3DS using GodMode9")
	ig.TextDisabled("See README for setup instructions")
	ig.PopFont()
}

app_show_select_file_screen :: proc(app: ^CitrustApp) {
	ig.PushFontFloat(app.font_large, app.font_large.LegacySize)
	ig.Text("citodin — 3DS ROM Decrypter")
	ig.PopFont()
	ig.Dummy({0, 30})

	ig.PushFontFloat(app.font_button, app.font_button.LegacySize)
	if ig.Button("📁 Select ROM File", {400, 80}) {
		filters := [?]sdl.DialogFileFilter{{"3DS ROM", "3ds"}}
		sdl.ShowOpenFileDialog(proc "c" (userdata: rawptr, filelist: [^]cstring, filter: c.int) {
			context = runtime.default_context()
			app := (^CitrustApp)(userdata)
			if filelist != nil && filelist[0] != nil {
				app.selected_file = string(filelist[0])
			}
		}, app, app.window, &filters[0], 1, nil, false)
	}
	ig.PopFont()

	if app.selected_file != "" {
		ig.Dummy({0, 15})
		ig.PushFontFloat(app.font_body, app.font_body.LegacySize)
		sel_cstr := strings.clone_to_cstring(fmt.tprintf("Selected: %s", app.selected_file), context.temp_allocator)
		ig.Text(sel_cstr)
		ig.Dummy({0, 10})

		ig.PushFontFloat(app.font_button, app.font_button.LegacySize)
		if ig.Button("🔓 Decrypt", {400, 80}) {
			app_start_decryption(app)
		}
		ig.PopFont()
		ig.PopFont()
	}

	if strings.has_prefix(app.key_save_message, "✅") {
		app_toast(app)
	}
}

app_start_decryption :: proc(app: ^CitrustApp) {
	app.progress = ProgressState{}
	app.progress.start_time = time.now()
	app.screen = .Decrypting

	thread.run_with_data(rawptr(app), proc(data: rawptr) {
		app_ptr := (^CitrustApp)(data)
		result := decrypt_rom(app_ptr.selected_file, &app_ptr.keydb, proc(msg: string, user_data: rawptr) {
			a := (^CitrustApp)(user_data)
			sync.mutex_lock(&a.progress.lock)
			append(&a.progress.messages, msg)
			if strings.has_prefix(msg, "Encryption Method:") {
				a.progress.encryption_method = msg
			}
			if strings.contains(msg, "ExeFS") || strings.contains(msg, "RomFS") {
				a.progress.current_section = msg
			}
			sync.mutex_unlock(&a.progress.lock)
		}, app_ptr)
		sync.mutex_lock(&app_ptr.progress.lock)
		app_ptr.progress.done = true
		if result != nil {
			app_ptr.progress.had_error = true
		}
		sync.mutex_unlock(&app_ptr.progress.lock)
	})
}

app_show_decrypting_screen :: proc(app: ^CitrustApp) {
	sync.mutex_lock(&app.progress.lock)
	current_section := app.progress.current_section
	encryption_method := app.progress.encryption_method
	messages := make([]string, len(app.progress.messages), context.temp_allocator)
	copy(messages, app.progress.messages[:])
	done := app.progress.done
	had_error := app.progress.had_error
	elapsed_secs := time.duration_seconds(time.since(app.progress.start_time))
	sync.mutex_unlock(&app.progress.lock)

	if done {
		app.screen = .Done
		return
	}

	ig.PushFontFloat(app.font_large, app.font_large.LegacySize)
	ig.Text("Decrypting...")
	ig.PopFont()
	ig.Dummy({0, 20})

	ig.PushFontFloat(app.font_body, app.font_body.LegacySize)
	str := strings.clone_to_cstring(fmt.tprintf("File: %s", app.selected_file), context.temp_allocator)
	ig.Text(str)
	ig.Dummy({0, 10})

	if encryption_method != "" {
		em_cstr := strings.clone_to_cstring(encryption_method, context.temp_allocator)
		ig.Text(em_cstr)
		ig.Dummy({0, 10})
	}

	if current_section != "" {
		ig.PushFontFloat(app.font_small, app.font_small.LegacySize)
		cs_cstr := strings.clone_to_cstring(current_section, context.temp_allocator)
		ig.Text(cs_cstr)
		ig.PopFont()
		ig.Dummy({0, 15})
	}

	elapsed_cstr := strings.clone_to_cstring(fmt.tprintf("Elapsed: %ds", int(elapsed_secs)), context.temp_allocator)
	ig.Text(elapsed_cstr)
	ig.Dummy({0, 15})
	ig.PopFont()

	ig.BeginChild("##progress_log", {800, 200})
	ig.PushFontFloat(app.font_small, app.font_small.LegacySize)
	for msg in messages {
		msg_cstr := strings.clone_to_cstring(msg, context.temp_allocator)
		ig.Text(msg_cstr)
	}
	if len(messages) > 0 {
		ig.SetScrollHereY(1.0)
	}
	ig.PopFont()
	ig.EndChild()

	if had_error {
		ig.Dummy({0, 10})
		ig.PushStyleColor(.Text, ig.ColorConvertFloat4ToU32({0.86, 0.31, 0.31, 1.0}))
		ig.Text("ERROR: Decryption failed")
		ig.PopStyleColor()
		ig.Dummy({0, 10})
		if ig.Button("Back") {
			app.screen = .SelectFile
		}
	}

	if !had_error {
		ig.Dummy({0, 10})
		ig.PushFontFloat(app.font_small, app.font_small.LegacySize)
		ig.TextDisabled("⚠️ Cannot cancel — decryption modifies file in-place")
		ig.PopFont()
	}
}

app_show_done_screen :: proc(app: ^CitrustApp) {
	ig.PushFontFloat(app.font_large, app.font_large.LegacySize)
	ig.Text("✅ Decryption Complete!")
	ig.PopFont()
	ig.Dummy({0, 20})

	ig.PushFontFloat(app.font_body, app.font_body.LegacySize)
	str := strings.clone_to_cstring(
		fmt.tprintf("Total time: %ds", int(time.duration_seconds(time.since(app.progress.start_time)))),
		context.temp_allocator)
	ig.Text(str)
	ig.Dummy({0, 30})
	ig.PopFont()

	ig.PushFontFloat(app.font_button, app.font_button.LegacySize)
	if ig.Button("🔄 Decrypt Another", {400, 80}) {
		app.progress = ProgressState{}
		app.screen = .SelectFile
	}
	ig.Dummy({0, 10})
	if ig.Button("❌ Quit", {400, 80}) {
		_ = sdl.PushEvent(&sdl.Event{type = .QUIT})
	}
	ig.PopFont()
}
