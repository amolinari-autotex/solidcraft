//! Layout checks over every toolbar command, headless (see `solidcraft_ui_egui::scenario`):
//! each command's dialog opens docked at the viewport's right within its width limits, and
//! every window it opens fits on screen.

use serde_json::{Value, json};
use solidcraft_ui_egui::scenario::{Harness, check, rect_of};

#[path = "support/raster.rs"]
mod pdm_layout_raster;

fn capture_pdm_history_layout(h: &mut Harness, layout: solidcraft_ui_egui::shell::LayoutMode) {
    let Ok(phase) = std::env::var("SOLIDCRAFT_PDM_LAYOUT_PROOF_PHASE") else { return };
    assert!(matches!(phase.as_str(), "before" | "after"));
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/pdm-6c60-layout-proof");
    std::fs::create_dir_all(&dir).unwrap();
    h.ctx = egui::Context::default();
    solidcraft_ui_egui::fonts::setup_fonts(&h.ctx);
    solidcraft_ui_egui::theme::apply(&h.ctx);
    let mut textures = std::collections::HashMap::new();
    for _ in 0..8 {
        pdm_layout_raster::paint(h, &mut textures, vec![]);
    }
    let output = pdm_layout_raster::paint(h, &mut textures, vec![]);
    pdm_layout_raster::raster(h, &textures, output)
        .save(dir.join(format!("{phase}-{layout:?}-labels-{}.png", h.app.preferences.ribbon_labels)))
        .unwrap();
}

#[test]
fn pdm_archive_ignores_editor_history_columns_in_both_layouts() {
    use solidcraft_ui_egui::{shell::LayoutMode, toolbar};

    for layout in [LayoutMode::Docked, LayoutMode::Floating] {
        for labels in [false, true] {
            let mut h = Harness::new();
            h.app.ui.layout = layout;
            h.app.preferences.ribbon_labels = labels;
            h.app.ui.show_browser = true;
            h.app.ui.show_timeline = true;
            h.app.preferences.timeline_left = false;
            h.app.preferences.timeline_under_browser = false;
            h.frames(4);
            let before = h.app.session.doc.clone();
            solidcraft_ui_egui::pdm_panel::enter(&mut h.app).unwrap();
            h.frames(4);
            let full = rect_of("pdm_footer").expect("the archive browser is visible");
            let ribbon = rect_of("toolbar").unwrap();
            assert_eq!(ribbon.height(), if labels { toolbar::RIBBON_HEIGHT } else { 93.0 });
            for action in ["pdm.connect", "pdm.checkout", "pdm.archive", "pdm.refresh"] {
                let button = rect_of(&format!("pdm_action_button:{action}")).expect("the archive action is present");
                assert!(
                    ribbon.contains_rect(button),
                    "archive action is outside the compact ribbon: {layout:?}, labels={labels}, {action}: {button:?} vs {ribbon:?}"
                );
            }
            assert!(rect_of("browser:card").is_none(), "the editor browser is hidden in PDM");
            assert!(rect_of("history:strip").is_none() && rect_of("history:card").is_none(), "the editor history is hidden in PDM");

            h.app.preferences.timeline_left = true;
            h.app.preferences.timeline_under_browser = true;
            for floating_browser in [false, true] {
                h.app.preferences.browser_float = floating_browser;
                h.frames(6);
                let actual = rect_of("pdm_footer").expect("the archive browser remains visible");
                if (actual.left() - full.left()).abs() > 1.0 {
                    capture_pdm_history_layout(&mut h, layout);
                }
                assert!((actual.left() - full.left()).abs() <= 1.0, "editor history reserved an archive column: {layout:?}, {actual:?} vs {full:?}");
                assert!((actual.right() - full.right()).abs() <= 1.0, "archive width changed with editor preferences: {layout:?}");
                assert!(h.app.pdm.workspace_active);
                assert_eq!(*h.app.session.doc, *before);
            }
            capture_pdm_history_layout(&mut h, layout);
        }
    }
}

#[test]
fn pdm_confirmation_hosts_preserve_cancel_and_connection_close_in_both_layouts() {
    use solidcraft_engine::pdm::Reference;
    use solidcraft_ui_egui::shell::LayoutMode;

    for layout in [LayoutMode::Docked, LayoutMode::Floating] {
        let mut h = Harness::new();
        h.app.ui.layout = layout;
        let before = h.app.session.doc.clone();
        h.app.pdm.open = true;
        h.frames(5);
        assert!(h.app.pdm.open);
        h.step(&json!({"click":{"handle":"pdm:connection_close"}})).unwrap();
        assert!(!h.app.pdm.open);
        h.app.pdm.open = true;
        h.frames(5);
        h.step(&json!({"click":{"handle":"dialog:close"}})).unwrap();
        assert!(!h.app.pdm.open, "the shared window close button retains the connection close behavior");
        h.app.pdm.restore_confirmation = Some(Reference { document: "part".into(), version: 1 });
        h.frames(5);
        assert!(h.app.pdm.restore_confirmation.is_some());
        h.step(&json!({"widget":h.app.tr("ui.cancel")})).unwrap();
        assert!(h.app.pdm.restore_confirmation.is_none(), "Cancel retains the restore confirmation behavior");
        assert!(h.app.pdm.runtime.status().unwrap().busy.is_none(), "closing a disconnected dialog issued no native operation");
        assert_eq!(*h.app.session.doc, *before);
    }
}

#[test]
fn pdm_start_page_entry_preserves_file_view_and_the_editor() {
    for (width, busy) in [(1400, false), (420, false), (1400, true)] {
        let mut h = Harness::new();
        h.app.run("solid.box", json!({"length":2,"width":3,"height":4})).unwrap();
        let before = h.app.session.doc.clone();
        let undo = h.app.session.undo.len();
        h.call("ui.resize", json!({"width":width,"height":900}));
        h.app.home.show(0);
        h.frames(5);
        assert!(rect_of("home:new_mm").is_some(), "the upstream File view remains available");
        if width < 500 {
            h.step(&json!({"widget":h.app.tr("ui.start_page")})).unwrap();
            h.frames(2);
        }
        if busy {
            h.app.services.pick_open = Some(Box::new(|_| Box::pin(std::future::pending())));
            h.step(&json!({"key":"O","cmd":true})).unwrap();
            h.frames(2);
            assert!(h.app.file_picker_busy());
        }
        h.step(&json!({"click":{"handle":"home:pdm"}})).unwrap();
        assert_eq!(h.app.pdm.workspace_active, !busy, "File view PDM entry follows the file-operation guard");
        assert_eq!(h.app.home.open, busy);
        assert_eq!(*h.app.session.doc, *before);
        assert_eq!(h.app.session.undo.len(), undo);
    }
}

/// A box body (its sketch finished) to give feature dialogs something to work on.
fn harness() -> Harness {
    let mut h = Harness::new();
    for (id, p) in [
        ("sketch.create", json!({"plane": "XY"})),
        ("sketch.rectangle.two_point", json!({"p0": [0, 0], "p1": [40, 30]})),
        ("sketch.finish", json!({})),
        ("solid.extrude", json!({"distance": 10})),
    ] {
        h.call("engine.execute", json!({"command": id, "params": p}));
    }
    h.frames(3);
    h
}

#[test]
fn every_dialog_opens_docked_within_its_width_limits() {
    let mut bad = Vec::new();
    let mut seen = 0;
    for spec in solidcraft_engine::command_specs() {
        if spec.tab.is_empty() || spec.tab == "SKETCH" {
            continue;
        }
        let mut h = harness();
        h.call("ui.start", json!({"command": spec.id}));
        h.frames(4);
        if h.app.dialog.is_some() {
            seen += 1;
            // Wide cards use the kit's bounded table/timeline width.
            let w = rect_of("dialog:outer").map_or(0.0, |r| r.width());
            let limits = if matches!(spec.id, "config.table" | "config.configure" | "motion.study") {
                let width = solidcraft_ui_egui::theme::Tokens::get().form_card_width * 3.0;
                json!({"min":width - 4.0,"max":width + 2.0})
            } else if w > 400.0 {
                json!({"min":480,"max":562})
            } else {
                json!({"min":260,"max":382})
            };
            if let Err(e) = check(&mut h, &json!({ "dialog_docked": limits })) {
                bad.push(format!("{}: {e}", spec.id));
            }
        }
        if let Err(e) = check(&mut h, &json!({"windows_fit": {"max_width": 900}})) {
            bad.push(format!("{}: {e}", spec.id));
        }
    }
    assert!(seen > 20, "only {seen} commands opened a dialog");
    assert!(bad.is_empty(), "{} problems:\n{}", bad.len(), bad.join("\n"));
}

/// Windows that are not command dialogs: each fits on screen.
#[test]
fn other_windows_fit_on_screen() {
    let mut bad = Vec::new();
    let opens: [(&str, Value); 3] = [("ui.help", json!({"item": "about"})), ("ui.key", json!({"key": "S"})), ("ui.prefs", json!({"open": true}))];
    for (m, p) in opens {
        let mut h = harness();
        h.call(m, p.clone());
        h.frames(4);
        if let Err(e) = check(&mut h, &json!({"windows_fit": {"max_width": 900}})) {
            bad.push(format!("{m} {p}: {e}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The docked ribbon reserves the same space in both themes and at narrow widths. The
/// existing panel menus and S box remain usable through the new painted hit targets.
#[test]
fn docked_ribbon_geometry_and_search() {
    use solidcraft_ui_egui::{scenario::handle_at, toolbar};
    for theme in ["light", "dark"] {
        let mut h = harness();
        h.call("ui.set", json!({"layout":"docked"}));
        h.app.preferences.theme = theme.into();
        for width in [1600.0, 640.0, 320.0] {
            h.call("ui.resize", json!({"width":width,"height":1000}));
            h.frames(4);
            let ribbon = rect_of("toolbar").unwrap();
            let workspace = rect_of("ribbon:workspace").unwrap();
            let search = rect_of("ribbon:search").unwrap();
            assert_eq!(ribbon.top(), toolbar::APP_BAR_HEIGHT);
            assert_eq!(ribbon.height(), 117.0);
            assert_eq!(ribbon.width(), width);
            assert_eq!(workspace.width(), 88.0);
            assert_eq!(workspace.top(), ribbon.top());
            assert_eq!(workspace.bottom(), ribbon.bottom() - 1.0);
            assert_eq!(toolbar::TAB_ROW_HEIGHT, 30.0);
            assert_eq!(search.height(), 22.0);
            assert_eq!(search.top(), ribbon.top() + 4.0);
            assert_eq!(search.right(), ribbon.right() - 4.0);
            assert_eq!(search.center().y, ribbon.top() + 15.0);
            let t = solidcraft_ui_egui::theme::Tokens::get();
            let (hint_width, key_width) = h.ctx.fonts_mut(|fonts| {
                (
                    fonts
                        .layout_no_wrap(
                            solidcraft_ui_egui::i18n::tr_label("Search commands").to_owned(),
                            egui::FontId::proportional(t.font_button),
                            t.form_dim,
                        )
                        .size()
                        .x,
                    fonts.layout_no_wrap("S".to_owned(), egui::FontId::monospace(t.font_small), t.form_dim).size().x,
                )
            });
            // Two outer paddings, two item gaps, and total keycap padding.
            assert_eq!(search.width(), (hint_width + key_width + t.space_16 + t.space_4 * 5.0 + t.space_2).ceil());
            assert!(ribbon.contains_rect(search));
            assert!(search.left() > workspace.right());
            assert!(h.app.viewport.rect.unwrap().top() >= toolbar::APP_BAR_HEIGHT + toolbar::RIBBON_HEIGHT);
            h.step(&json!({"click":{"handle":"ribbon:search"}})).unwrap();
            assert!(h.app.ui.palette_open);
            h.frames(10);
            let field = rect_of("ribbon:search").unwrap();
            assert_eq!(field.width(), 520.0_f32.min(width - 8.0));
            assert_eq!(field.height(), 40.0);
            assert_eq!(field.right(), search.right());
            assert_eq!(Some(field), rect_of("shortcut:search"));
            assert_eq!(Some(field), rect_of("palette:search"));
            let popup = rect_of("ribbon:search_popup").unwrap();
            assert_eq!(popup.top(), field.bottom() + solidcraft_ui_egui::theme::Tokens::get().space_6);
            assert_eq!(popup.x_range(), field.x_range());
            assert!(popup.top() >= search.bottom());
            assert!(popup.left() <= search.left());
            h.step(&json!({"key":"Escape"})).unwrap();
            assert!(!h.app.ui.palette_open);
            h.frames(10);
            assert_eq!(rect_of("ribbon:search").unwrap(), search);
            h.step(&json!({"key":"S"})).unwrap();
            assert!(h.app.ui.palette_open);
            h.frames(10);
            assert_eq!(rect_of("ribbon:search_popup").unwrap().min, popup.min);
            h.step(&json!({"key":"Escape"})).unwrap();
            h.frames(10);
        }
        h.call("ui.resize", json!({"width":1600,"height":1000}));
        h.frames(4);
        let button = rect_of("button:solid.extrude").unwrap();
        assert_eq!(button.height(), 60.0);
        assert!(button.width() >= 54.0);
        let section = rect_of("ribbon:section:MODEL:CREATE").unwrap();
        assert_eq!(section.height(), 20.0);
        assert!(section.top() > button.bottom());
        assert_eq!(section.bottom(), rect_of("toolbar").unwrap().bottom() - 4.0);
        assert_eq!(handle_at("panel:MODEL:CREATE"), handle_at("ribbon:section:MODEL:CREATE"));
        h.step(&json!({"click":{"handle":"ribbon:section:MODEL:CREATE"}})).unwrap();
        assert!(rect_of("toolbar_dropdown").is_some());
        h.step(&json!({"key":"Escape"})).unwrap();
        h.step(&json!({"click":{"handle":"ribbon:workspace"}})).unwrap();
        assert!(h.app.viewport.context_menu.is_some());
    }
}

#[test]
fn finish_sketch_stays_at_the_right_when_groups_collapse() {
    use solidcraft_ui_egui::scenario::{count_of, handle_at};
    for layout in ["docked", "floating"] {
        let mut h = Harness::new();
        h.call("ui.set", json!({"layout":layout}));
        h.call("engine.execute", json!({"command":"sketch.create","params":{"plane":"XY"}}));
        for width in [1600.0, 640.0, 320.0] {
            h.call("ui.resize", json!({"width":width,"height":1000}));
            h.frames(5);
            let ribbon = rect_of("toolbar").unwrap();
            let exit = rect_of("ribbon:section:SKETCH:FINISH SKETCH").unwrap();
            let finish = rect_of("button:sketch.finish").unwrap();
            // Finish follows the last sketch panel; once panels spill into the » menu it sits at
            // the right end, after it.
            if count_of("toolbar_more").unwrap_or(0.0) > 0.0 {
                assert_eq!(exit.right(), ribbon.right() - 4.0, "{layout} at {width}");
            } else {
                assert!(exit.right() <= ribbon.right() - 4.0, "{layout} at {width}");
                let last = rect_of("panel:SKETCH:CONFIGURE").or_else(|| rect_of("panel:SKETCH:REFERENCE")).unwrap();
                let group = rect_of("panel:SKETCH:FINISH SKETCH").unwrap();
                assert!(group.left() - last.right() < 16.0, "{layout} at {width}: Finish follows the last panel");
            }
            assert!(ribbon.contains_rect(finish));
            assert!(finish.bottom() < exit.top());
            assert!(handle_at("tab:SKETCH").is_some(), "the selected contextual tab scrolls into view");
        }
        h.step(&json!({"click":{"handle":"button:sketch.finish"}})).unwrap();
        assert!(h.app.session.active_sketch.is_none());
    }
}
