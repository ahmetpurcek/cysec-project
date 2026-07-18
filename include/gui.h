/*
 * gui.h — raylib GUI Modülü (v2 - Yeniden Tasarım)
 */
#ifndef GUI_H
#define GUI_H
#include "raylib.h"

/* ========== Renkler (Modern Dark) ========== */
#define COLOR_BG            (Color){  8,  10,  18, 255 }
#define COLOR_PANEL         (Color){ 14,  18,  30, 255 }
#define COLOR_PANEL_HOVER   (Color){ 22,  28,  48, 255 }
#define COLOR_BORDER        (Color){ 30,  40,  65, 160 }
#define COLOR_ACCENT        (Color){ 99, 102, 241, 255 }
#define COLOR_ACCENT2       (Color){139,  92, 246, 255 }
#define COLOR_GREEN         (Color){ 16, 185, 129, 255 }
#define COLOR_AMBER         (Color){245, 158,  11, 255 }
#define COLOR_RED           (Color){239,  68,  68, 255 }
#define COLOR_CYAN          (Color){  6, 182, 212, 255 }
#define COLOR_TEXT          (Color){226, 232, 240, 255 }
#define COLOR_TEXT_SEC      (Color){148, 163, 184, 255 }
#define COLOR_TEXT_DIM      (Color){ 71,  85, 105, 255 }
#define COLOR_SURFACE       (Color){ 20,  24,  40, 255 }
#define COLOR_SURFACE2      (Color){ 26,  32,  52, 255 }
#define COLOR_HEADER_BG     (Color){ 10,  13,  22, 255 }
#define COLOR_SELECTED      (Color){ 99, 102, 241,  25 }
#define COLOR_SCROLLBAR     (Color){ 55,  65,  95, 150 }
#define COLOR_TERMINAL_BG   (Color){  6,   8,  14, 255 }

/* ========== Tabs ========== */
typedef enum {
    TAB_DASHBOARD = 0,
    TAB_SECURITY,
    TAB_TOOLS,
    TAB_COUNT
} GuiTab;

void gui_init(int width, int height);
void gui_cleanup(void);
void gui_draw(void);
int  gui_should_close(void);
void gui_select_device(const char *ip);

#endif
