//! Native desktop entry point for UninstallAny.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod fonts;
mod worker;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1152.0, 744.0])
            .with_min_inner_size([720.0, 560.0]),
        ..eframe::NativeOptions::default()
    };
    eframe::run_native(
        "UninstallAny",
        options,
        Box::new(|creation| {
            let context = &creation.egui_ctx;
            let worker = worker::Worker::start(context.clone());
            let app = app::DesktopApp::new(context, worker);
            fonts::load_in_background(context.clone());
            Ok(Box::new(app))
        }),
    )
}
