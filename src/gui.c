/*
 * gui.c — raylib + raygui ile native GUI
 */
#include "gui.h"
#include "arp_scanner.h"
#include "brute_force.h"
#include "log_analyzer.h"
#include "network_monitor.h"
#include "platform.h"
#include "port_scanner.h"
#include "raylib.h"
#include "utils.h"

#define RAYGUI_IMPLEMENTATION
#include "../lib/raygui.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

/* ========== State ========== */
static GuiTab g_active_tab = TAB_DASHBOARD;
static ScanResults g_scan;
static AnalysisResult g_analysis;
static ScanLog g_scanlog;
static float g_scroll_devices = 0;
static float g_scroll_alerts = 0;
static float g_scroll_rawlog = 0;
static char g_selected_device_ip[MAX_IP_LEN] = {0};
static double g_last_refresh = 0;
static char g_raw_log_source[32] = "journal";
static char g_raw_log_lines[200][256];
static int g_raw_log_count = 0;
static PortScanResults g_portscan;
static float g_scroll_pcap_flows = 0;
static float g_scroll_device_detail = 0;
static int g_security_subtab = 0;      /* 0=alerts, 1=logs */
static int g_tools_subtab = 0;         /* 0=Port Tarayici, 1=Brute Force */
static float g_scroll_tool_ports = 0;
static int g_selected_packet_num = -1;
static float g_scroll_pdu_detail = 0;
static int g_ps_selected_vuln_port = -1; /* secili port vulnerability detail */
static float g_scroll_ps_devices = 0;    /* port scanner cihaz listesi scroll */
static float g_scroll_bf_devices = 0;    /* brute force cihaz listesi scroll */
static int g_selected_layer = -1;
static char g_capture_active_ip[MAX_IP_LEN] = {0}; /* aktif trafik izleme yapilan cihaz */


static Font g_custom_font = {0};
static float g_ui_scale = 1.0f;

/* ========== Yardımcılar ========== */
static void BeginScissorModeScaled(int x, int y, int width, int height) {
  BeginScissorMode((int)(x * g_ui_scale), (int)(y * g_ui_scale), (int)(width * g_ui_scale), (int)(height * g_ui_scale));
}

static void DrawTextC(const char *text, int x, int y, int size, Color color) {
  if (g_custom_font.texture.id > 0) {
    DrawTextEx(g_custom_font, text, (Vector2){(float)x, (float)y}, (float)size,
               1.0f, color);
  } else {
    DrawText(text, x, y, size, color);
  }
}

static void DrawRoundedPanel(Rectangle r, Color bg, Color border) {
  DrawRectangleRounded(r, 0.04f, 8, bg);
  DrawRectangleRoundedLinesEx(r, 0.04f, 8, 1.0f, border);
}

static void draw_custom_scrollbar(float x, float y, float w, float view_h,
                                  float content_h, float *scroll) {
  if (content_h <= view_h)
    return;
  float max_scroll = content_h - view_h;
  float thumb = view_h * (view_h / content_h);
  if (thumb < 20)
    thumb = 20;

  Rectangle track = {x, y, w, view_h};
  if (CheckCollisionPointRec(GetMousePosition(), track)) {
    if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
      float my = GetMousePosition().y - y;
      float percent = (my - thumb / 2) / (view_h - thumb);
      if (percent < 0)
        percent = 0;
      if (percent > 1.0f)
        percent = 1.0f;
      *scroll = percent * max_scroll;
    }
  }

  float thumb_y = y + (*scroll / max_scroll) * (view_h - thumb);
  DrawRectangleRounded(track, 0.5f, 4, (Color){30, 40, 65, 50});
  DrawRectangleRounded((Rectangle){x, thumb_y, w, thumb}, 0.5f, 4,
                       COLOR_SCROLLBAR);
}

/* Forward declaration — trafik yakalama yardımcıları */
static void capture_stop_all(void);

/* ========== Header ========== */
static void draw_header(int W) {
  DrawRectangle(0, 0, W, 48, COLOR_HEADER_BG);
  DrawRectangle(0, 47, W, 1, COLOR_BORDER);

  /* Gradient accent line at top */
  for (int i = 0; i < W; i++) {
    float t = (float)i / W;
    Color c = {(unsigned char)(99 * (1 - t) + 139 * t),
               (unsigned char)(102 * (1 - t) + 92 * t),
               (unsigned char)(241 * (1 - t) + 246 * t), 255};
    DrawRectangle(i, 0, 1, 2, c);
  }

  DrawTextC("SecurCity", 16, 10, 22, COLOR_TEXT);
  DrawTextC("Network Security", 16, 30, 10, COLOR_ACCENT);

  /* Saat */
  char clock[16];
  time_now_hms(clock, sizeof(clock));
  int cw = MeasureText(clock, 14);
  DrawTextC(clock, W - cw - 16, 18, 14, COLOR_TEXT_DIM);

  /* Status dot */
  DrawCircle(W - cw - 28, 24, 3, COLOR_GREEN);
}

/* ========== Tab Bar ========== */
static void draw_tabs(int W) {
  int y = 50;
  DrawRectangle(0, y, W, 32, COLOR_PANEL);
  DrawRectangle(0, y + 31, W, 1, COLOR_BORDER);

  const char *labels[] = {"Dashboard", "Guvenlik", "Araclar"};
  int tx = 12;
  for (int i = 0; i < (int)TAB_COUNT; i++) {
    int tw = MeasureText(labels[i], 13) + 28;
    Rectangle btn = {(float)tx, (float)y + 3, (float)tw, 26};
    int hover = CheckCollisionPointRec(GetMousePosition(), btn);
    if (i == (int)g_active_tab) {
      DrawRectangleRounded(btn, 0.4f, 6, COLOR_SELECTED);
      DrawRectangle(tx, y + 27, tw, 2, COLOR_ACCENT);
      DrawTextC(labels[i], tx + 14, y + 9, 13, COLOR_ACCENT);
    } else {
      if (hover)
        DrawRectangleRounded(btn, 0.4f, 6, (Color){255, 255, 255, 6});
      DrawTextC(labels[i], tx + 14, y + 9, 13,
                hover ? COLOR_TEXT : COLOR_TEXT_SEC);
    }
    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      g_active_tab = i;
      /* Tab değişince aktif izlemeyi durdur */
      if (g_capture_active_ip[0]) capture_stop_all();
      if (i == TAB_DASHBOARD) {
        g_selected_device_ip[0] = '\0';
        g_scroll_devices = 0;
        g_selected_packet_num = -1;
      }
    }
    tx += tw + 4;
  }
}

/* ========== Stat Card ========== */
static void draw_stat_card(Rectangle r, const char *label, const char *value,
                           Color valColor, const char *sub) {
  DrawRoundedPanel(r, COLOR_SURFACE, COLOR_BORDER);
  DrawTextC(label, r.x + 12, r.y + 10, 10, COLOR_TEXT_SEC);
  DrawTextC(value, r.x + 12, r.y + 26, 18, valColor);
  if (sub && sub[0])
    DrawTextC(sub, r.x + 12, r.y + 48, 10, COLOR_TEXT_DIM);
}

/* ========== Dashboard Paneli ========== */
static void draw_right_panel_logs(int rx, int ry, int rw, int rh);
static void draw_right_panel_device(int rx, int ry, int rw, int rh);

static void draw_panel_dashboard(int W, int H) {
  int y0 = 86;
  int cw = (W - 36) / 3;
  char buf[64], sub[128];

  snprintf(buf, sizeof(buf), "%d", g_scan.total);
  snprintf(sub, sizeof(sub), "%s",
           g_scan.network_range[0] ? g_scan.network_range : "...");
  draw_stat_card((Rectangle){12, y0, cw - 4, 60}, "Cihaz", buf, COLOR_ACCENT,
                 sub);

  snprintf(buf, sizeof(buf), "%s",
           g_scan.gateway_ip[0] ? g_scan.gateway_ip : "...");
  draw_stat_card((Rectangle){12 + cw, y0, cw - 4, 60}, "Gateway", buf,
                 COLOR_GREEN, NULL);

  snprintf(buf, sizeof(buf), "%s",
           g_scan.local_ip[0] ? g_scan.local_ip : "...");
  draw_stat_card((Rectangle){12 + cw * 2, y0, cw - 4, 60}, "Bu Cihaz", buf,
                 COLOR_CYAN, NULL);

  /* Sol: Cihaz listesi | Sag: Detay veya Log */
  int list_w = 280;
  int right_w = W - 24 - list_w - 8;
  int list_y = y0 + 68;
  int list_h = H - list_y - 8;

  /* Sol panel */
  DrawRoundedPanel((Rectangle){12, list_y, list_w, list_h}, COLOR_PANEL,
                   COLOR_BORDER);
  DrawTextC("Agdaki Cihazlar", 24, list_y + 8, 12, COLOR_ACCENT);

  /* Tarama badge */
  {
    DrawCircle(12 + list_w - 14, list_y + 14, 3,
               g_scan.is_scanning ? COLOR_AMBER : COLOR_GREEN);
  }

  int item_h = 36;
  int visible_items = (list_h - 32) / item_h;
  float max_scroll = (g_scan.device_count - visible_items) * item_h;
  if (max_scroll < 0)
    max_scroll = 0;

  Rectangle list_area = {12, list_y + 26, list_w, list_h - 30};
  if (CheckCollisionPointRec(GetMousePosition(), list_area)) {
    g_scroll_devices -= GetMouseWheelMove() * 30;
    if (g_scroll_devices < 0)
      g_scroll_devices = 0;
    if (g_scroll_devices > max_scroll)
      g_scroll_devices = max_scroll;
  }

  BeginScissorModeScaled(12, list_y + 26, list_w, list_h - 30);
  for (int i = 0; i < g_scan.device_count; i++) {
    int iy = list_y + 28 + i * item_h - (int)g_scroll_devices;
    if (iy + item_h < list_y + 26 || iy > list_y + list_h)
      continue;

    Device *d = &g_scan.devices[i];
    Rectangle item_r = {16, iy, list_w - 24, item_h - 3};
    int is_sel = (strcmp(d->ip, g_selected_device_ip) == 0);
    int hover = CheckCollisionPointRec(GetMousePosition(), item_r);

    Color bg = is_sel ? COLOR_SELECTED
                      : (hover ? COLOR_PANEL_HOVER : (Color){0, 0, 0, 0});
    if (is_sel || hover)
      DrawRectangleRounded(item_r, 0.1f, 6, bg);
    if (is_sel)
      DrawRectangle(item_r.x, item_r.y + 4, 3, item_r.height - 8, COLOR_ACCENT);

    DrawTextC(d->ip, item_r.x + 14, item_r.y + 11, 13,
              is_sel ? COLOR_ACCENT : COLOR_TEXT);

    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      if (is_sel) {
        /* Cihaz deselect — aktif izleme varsa durdur */
        if (g_capture_active_ip[0] &&
            strcmp(g_capture_active_ip, d->ip) == 0) {
          capture_stop_all();
        }
        g_selected_device_ip[0] = '\0';
        g_selected_packet_num = -1;
      } else {
        /* Başka cihaz seçildi — eski izleme varsa durdur */
        if (g_capture_active_ip[0] &&
            strcmp(g_capture_active_ip, g_selected_device_ip) == 0) {
          capture_stop_all();
        }
        strncpy(g_selected_device_ip, d->ip, MAX_IP_LEN - 1);
        g_scroll_device_detail = 0;
        g_selected_packet_num = -1;
      }
    }
  }
  EndScissorMode();

  draw_custom_scrollbar(12 + list_w - 10, list_y + 26, 10, list_h - 30,
                        g_scan.device_count * item_h, &g_scroll_devices);

  /* Sag panel */
  int rx = 12 + list_w + 8;
  int ry = list_y;
  int rw = right_w;
  int rh = list_h;

  if (g_selected_device_ip[0]) {
    draw_right_panel_device(rx, ry, rw, rh);
  } else {
    draw_right_panel_logs(rx, ry, rw, rh);
  }
}

/* Sag panel: Tarama loglari (cihaz secili degilken) */
static void draw_right_panel_logs(int rx, int ry, int rw, int rh) {
  DrawRoundedPanel((Rectangle){rx, ry, rw, rh}, COLOR_PANEL, COLOR_BORDER);
  DrawTextC("Tarama Loglari", rx + 12, ry + 8, 12, COLOR_ACCENT);

  char sc[32];
  snprintf(sc, sizeof(sc), "#%d", g_scan.scan_count);
  int scw = MeasureText(sc, 10);
  DrawTextC(sc, rx + rw - scw - 12, ry + 10, 10, COLOR_TEXT_DIM);

  DrawRectangle(rx + 4, ry + 26, rw - 8, 1, COLOR_BORDER);

  BeginScissorModeScaled(rx, ry + 30, rw, rh - 34);
  int log_y = ry + 32;
  for (int i = 0; i < g_scanlog.count; i++) {
    int idx =
        (g_scanlog.write_idx - g_scanlog.count + i + MAX_SCAN_LOG_LINES * 2) %
        MAX_SCAN_LOG_LINES;
    if (idx < 0 || idx >= MAX_SCAN_LOG_LINES)
      continue;
    Color lc = str_contains(g_scanlog.lines[idx], "hata")      ? COLOR_RED
               : str_contains(g_scanlog.lines[idx], "bulundu") ? COLOR_GREEN
                                                               : COLOR_TEXT_DIM;
    DrawTextC(g_scanlog.lines[idx], rx + 8, log_y + i * 14, 10, lc);
  }
  EndScissorMode();
}

/* --- Trafik yakalama yardımcıları (per-device capture) --- */
static void capture_stop_all(void) {
  if (arp_spoof_is_running()) arp_spoof_stop();
  full_monitor_stop();
  full_monitor_clear();
  g_capture_active_ip[0] = '\0';
}

static void capture_start_for(const char *ip) {
  /* Önce varsa eskisini durdur */
  capture_stop_all();

  /* Buffer'ı temizle */
  full_monitor_clear();

  /* Hedef IP'yi kaydet */
  strncpy(g_capture_active_ip, ip, MAX_IP_LEN - 1);

  /* pcap'i başlat */
  full_monitor_start(NULL);

  /* Yerel cihaz değilse ARP spoof başlat */
  int is_local = (strcmp(ip, g_scan.local_ip) == 0);
  if (!is_local && g_scan.gateway_ip[0] && g_scan.local_iface[0]) {
    arp_spoof_start(ip, g_scan.gateway_ip, g_scan.local_iface);
  }
}

/* Sag panel: Secili cihaz detayi (Wireshark tarzi Packet List + PDU Detail) */
static void draw_right_panel_device(int rx, int ry, int rw, int rh) {
  DrawRoundedPanel((Rectangle){rx, ry, rw, rh}, COLOR_PANEL, COLOR_BORDER);

  /* Baslik */
  char tbuf[128];
  snprintf(tbuf, sizeof(tbuf), "Cihaz Trafigi: %s", g_selected_device_ip);
  DrawTextC(tbuf, rx + 12, ry + 8, 14, COLOR_ACCENT);

  /* Kapat (X) butonu */
  Rectangle xbtn = {rx + rw - 28, ry + 6, 20, 20};
  int xhov = CheckCollisionPointRec(GetMousePosition(), xbtn);
  if (xhov)
    DrawRectangleRounded(xbtn, 0.3f, 4, (Color){255, 255, 255, 12});
  DrawTextC("X", rx + rw - 22, ry + 9, 12, xhov ? COLOR_RED : COLOR_TEXT_DIM);
  if (xhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
    /* Panel kapatılınca aktif izleme de durur */
    if (g_capture_active_ip[0] &&
        strcmp(g_capture_active_ip, g_selected_device_ip) == 0) {
      capture_stop_all();
    }
    g_selected_device_ip[0] = '\0';
    g_selected_packet_num = -1;
    return;
  }

  DrawRectangle(rx + 4, ry + 28, rw - 8, 1, COLOR_BORDER);

  /* --- Trafik Yakala / Durdur kontrolü (TÜM cihazlar için) --- */
  int capture_for_this = (g_capture_active_ip[0] &&
                          strcmp(g_capture_active_ip, g_selected_device_ip) == 0);
  int capture_for_other = (g_capture_active_ip[0] && !capture_for_this);

  {
    int btn_x = rx + rw - 160;
    int btn_y = ry + 6;

    if (capture_for_this) {
      /* Aktif izleme: Yeşil dot + "Izleniyor" + Durdur butonu */
      DrawCircle(btn_x - 8, btn_y + 10, 4, COLOR_GREEN);
      DrawTextC("Izleniyor", btn_x - 58, btn_y + 5, 9, COLOR_GREEN);
      Rectangle stop_btn = {btn_x, btn_y, 82, 18};
      DrawRectangleRounded(stop_btn, 0.4f, 4, (Color){239, 68, 68, 30});
      DrawRectangleRoundedLinesEx(stop_btn, 0.4f, 4, 1, COLOR_RED);
      int shov = CheckCollisionPointRec(GetMousePosition(), stop_btn);
      DrawTextC("Durdur", btn_x + 20, btn_y + 4, 9,
                shov ? COLOR_RED : (Color){239, 130, 130, 255});
      if (shov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        capture_stop_all();
        capture_for_this = 0;
      }
    } else if (capture_for_other) {
      /* Başka cihaz izleniyor — önce onu durdur */
      DrawTextC("Baska cihaz izleniyor", btn_x - 80, btn_y + 5, 8, COLOR_AMBER);
      Rectangle cap_btn = {btn_x, btn_y, 110, 18};
      DrawRectangleRounded(cap_btn, 0.4f, 4, (Color){99, 102, 241, 20});
      DrawRectangleRoundedLinesEx(cap_btn, 0.4f, 4, 1, COLOR_ACCENT);
      int chov = CheckCollisionPointRec(GetMousePosition(), cap_btn);
      DrawTextC("Degistir", btn_x + 22, btn_y + 4, 9,
                chov ? COLOR_ACCENT : COLOR_TEXT_SEC);
      if (chov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        capture_start_for(g_selected_device_ip);
        capture_for_this = 1;
      }
    } else {
      /* Pasif: "Trafik Yakala" butonu */
      Rectangle cap_btn = {btn_x, btn_y, 110, 18};
      DrawRectangleRounded(cap_btn, 0.4f, 4, (Color){99, 102, 241, 20});
      DrawRectangleRoundedLinesEx(cap_btn, 0.4f, 4, 1, COLOR_ACCENT);
      int chov = CheckCollisionPointRec(GetMousePosition(), cap_btn);
      DrawTextC("Trafik Yakala", btn_x + 10, btn_y + 4, 9,
                chov ? COLOR_ACCENT : COLOR_TEXT_SEC);
      if (chov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        capture_start_for(g_selected_device_ip);
        capture_for_this = 1;
      }
    }
  }

  /* --- Paket listesi (sadece bu cihaz için aktif izleme varsa göster) --- */
  static PacketRecord all_packets[2048];
  static PacketRecord dev_packets[1024];
  int dpc = 0;

  if (capture_for_this) {
    int c = full_monitor_get_packets(all_packets, 2048, 0);
    for (int i = 0; i < c; i++) {
      if (strcmp(all_packets[i].src_ip, g_selected_device_ip) == 0 ||
          strcmp(all_packets[i].dst_ip, g_selected_device_ip) == 0 ||
          strcmp(all_packets[i].src_mac, g_selected_device_ip) == 0 ||
          strcmp(all_packets[i].dst_mac, g_selected_device_ip) == 0) {
        if (dpc < 1024)
          dev_packets[dpc++] = all_packets[i];
      }
    }
  }

  int py = ry + 36;
  char buf[256];
  if (capture_for_this) {
    snprintf(buf, sizeof(buf), "Yakalanan Paket: %d", dpc);
    DrawTextC(buf, rx + 8, py, 10, COLOR_GREEN);
  } else {
    DrawTextC("Izleme baslatilmadi.", rx + 8, py, 10, COLOR_TEXT_DIM);
  }

  if (g_selected_packet_num != -1) {
    if (GuiButton((Rectangle){rx + rw - 80, py - 2, 70, 18}, "Geri Don")) {
      g_selected_packet_num = -1;
      g_scroll_pdu_detail = 0;
    }
  }

  py += 16;

  if (g_selected_packet_num == -1) {
    /* Paket Listesi Görünümü */
    DrawRectangle(rx + 4, py, rw - 8, 16, COLOR_SURFACE);
    DrawTextC("No", rx + 10, py + 3, 9, COLOR_TEXT_SEC);
    DrawTextC("Zaman", rx + 40, py + 3, 9, COLOR_TEXT_SEC);
    DrawTextC("Kaynak", rx + 90, py + 3, 9, COLOR_TEXT_SEC);
    DrawTextC("Hedef", rx + 190, py + 3, 9, COLOR_TEXT_SEC);
    DrawTextC("Proto", rx + 290, py + 3, 9, COLOR_TEXT_SEC);
    DrawTextC("Bilgi", rx + 330, py + 3, 9, COLOR_TEXT_SEC);
    py += 18;

    if (dpc == 0) {
      DrawTextC("Henuz cihaz trafigi yakalanmadi.", rx + 8, py + 20, 11,
                COLOR_TEXT_DIM);
    } else {
      int lh = rh - (py - ry) - 4;
      float ms = dpc * 18 - lh;
      if (ms < 0)
        ms = 0;
      Rectangle fa = {rx, py, rw, lh};
      if (CheckCollisionPointRec(GetMousePosition(), fa)) {
        g_scroll_pcap_flows -= GetMouseWheelMove() * 25;
        if (g_scroll_pcap_flows < 0)
          g_scroll_pcap_flows = 0;
        if (g_scroll_pcap_flows > ms)
          g_scroll_pcap_flows = ms;
      }
      BeginScissorModeScaled(rx, py, rw, lh);
      for (int i = 0; i < dpc; i++) {
        int iy = py + i * 18 - (int)g_scroll_pcap_flows;
        if (iy + 18 < py || iy > py + lh)
          continue;
        PacketRecord *p = &dev_packets[i];

        Rectangle pr = {rx + 4, iy, rw - 24, 17};
        int hover = CheckCollisionPointRec(GetMousePosition(), pr);
        Color rbg =
            hover ? COLOR_PANEL_HOVER
                  : ((i % 2 == 0) ? (Color){12, 16, 28, 255} : COLOR_SURFACE);
        DrawRectangleRec(pr, rbg);

        Color pc = strcmp(p->protocol, "TCP") == 0
                       ? COLOR_CYAN
                       : (strcmp(p->protocol, "UDP") == 0 ? COLOR_ACCENT2
                                                          : COLOR_TEXT);
        if (strcmp(p->protocol, "DNS") == 0 ||
            strcmp(p->protocol, "HTTP") == 0 || strcmp(p->protocol, "TLS") == 0)
          pc = COLOR_GREEN;
        if (strcmp(p->protocol, "ARP") == 0)
          pc = COLOR_AMBER;
        if (strcmp(p->protocol, "ICMP") == 0)
          pc = COLOR_RED;

        char sbuf[32];
        snprintf(sbuf, sizeof(sbuf), "%d", p->packet_number);
        DrawTextC(sbuf, rx + 10, iy + 3, 9, COLOR_TEXT_DIM);
        snprintf(sbuf, sizeof(sbuf), "%.2f", p->timestamp - (int)p->timestamp);
        DrawTextC(sbuf, rx + 40, iy + 3, 9, COLOR_TEXT_SEC);

        DrawTextC(p->src_ip[0] ? p->src_ip : p->src_mac, rx + 90, iy + 3, 9,
                  COLOR_TEXT);
        DrawTextC(p->dst_ip[0] ? p->dst_ip : p->dst_mac, rx + 190, iy + 3, 9,
                  COLOR_TEXT);

        DrawTextC(p->protocol, rx + 290, iy + 3, 9, pc);

        char infoshort[128];
        strncpy(infoshort, p->info, 127);
        infoshort[127] = '\0';
        for (int c = 0; c < 127 && infoshort[c]; c++)
          if (infoshort[c] == '\n' || infoshort[c] == '\r')
            infoshort[c] = ' ';
        DrawTextC(infoshort, rx + 330, iy + 3, 9, COLOR_TEXT_DIM);

        if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
          g_selected_packet_num = p->packet_number;
          g_scroll_pdu_detail = 0;
          g_selected_layer = -1;
        }
      }
      EndScissorMode();
      draw_custom_scrollbar(rx + rw - 10, py, 10, lh, dpc * 18,
                            &g_scroll_pcap_flows);
    }
  } else {
    /* Detaylı PDU Görünümü (Wireshark tarzı) */
    PacketRecord *sel_p = NULL;
    for (int i = 0; i < dpc; i++) {
      if (dev_packets[i].packet_number == g_selected_packet_num) {
        sel_p = &dev_packets[i];
        break;
      }
    }

    if (!sel_p) {
      g_selected_packet_num = -1;
      return;
    }

    int lh = rh - (py - ry) - 4;
    Rectangle da = {rx, py, rw, lh};

    /* Detay scroll limiti hesabı (dinamik) */
    float ms = 0;
    int d_y = 0;
    for (int i = 0; i < sel_p->layer_count; i++) {
      d_y += 24;
      if (g_selected_layer == i) {
        // Fields kaç satır?
        int lines = 1;
        for (int c = 0; sel_p->layers[i].fields[c]; c++)
          if (sel_p->layers[i].fields[c] == '\n')
            lines++;
        d_y += lines * 14 + 10;
      }
    }
    d_y += 30; /* Hex dump başlığı */
    d_y += ((sel_p->raw_len + 15) / 16) * 14 + 10;
    ms = d_y - lh;
    if (ms < 0)
      ms = 0;

    if (CheckCollisionPointRec(GetMousePosition(), da)) {
      g_scroll_pdu_detail -= GetMouseWheelMove() * 25;
      if (g_scroll_pdu_detail < 0)
        g_scroll_pdu_detail = 0;
      if (g_scroll_pdu_detail > ms)
        g_scroll_pdu_detail = ms;
    }

    BeginScissorModeScaled(rx, py, rw, lh);
    int cy = py - (int)g_scroll_pdu_detail;

    for (int i = 0; i < sel_p->layer_count; i++) {
      PduLayer *l = &sel_p->layers[i];

      Rectangle lr = {rx + 8, cy, rw - 28, 22};
      int hover = CheckCollisionPointRec(GetMousePosition(), lr);
      DrawRectangleRec(lr, hover ? COLOR_PANEL_HOVER : COLOR_SURFACE2);
      DrawRectangleLinesEx(lr, 1, COLOR_BORDER);

      char lhead[512];
      snprintf(lhead, sizeof(lhead), "%s %s: %s",
               g_selected_layer == i ? "v" : ">", l->name, l->summary);
      DrawTextC(lhead, rx + 14, cy + 5, 11, COLOR_ACCENT);

      if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        if (g_selected_layer == i)
          g_selected_layer = -1;
        else
          g_selected_layer = i;
      }
      cy += 24;

      if (g_selected_layer == i) {
        char tmpf[1024];
        strncpy(tmpf, l->fields, 1023);
        tmpf[1023] = '\0';
        char *line = strtok(tmpf, "\n");
        while (line != NULL) {
          DrawTextC(line, rx + 30, cy, 10, COLOR_TEXT_SEC);
          cy += 14;
          line = strtok(NULL, "\n");
        }
        cy += 10;
      }
    }

    cy += 10;
    DrawTextC("Frame Hex Dump", rx + 12, cy, 11, COLOR_TEXT);
    cy += 18;

    for (int r = 0; r < sel_p->raw_len; r += 16) {
      char hexp[64] = {0};
      char ascp[32] = {0};
      snprintf(hexp, sizeof(hexp), "%04X  ", r);
      for (int c = 0; c < 16; c++) {
        if (r + c < sel_p->raw_len) {
          char hb[8];
          snprintf(hb, sizeof(hb), "%02X ", sel_p->raw_data[r + c]);
          strcat(hexp, hb);
          char ch = sel_p->raw_data[r + c];
          ascp[c] = (ch >= 32 && ch <= 126) ? ch : '.';
        } else {
          strcat(hexp, "   ");
          ascp[c] = ' ';
        }
      }
      ascp[16] = '\0';

      DrawTextC(hexp, rx + 12, cy, 10, COLOR_TEXT_SEC);
      DrawTextC(ascp, rx + 300, cy, 10, COLOR_TEXT);
      cy += 14;
    }

    EndScissorMode();
    draw_custom_scrollbar(rx + rw - 10, py, 10, lh, d_y, &g_scroll_pdu_detail);
  }
}

/* ========== Guvenlik Paneli (Uyarilar + Loglar) ========== */
static void draw_panel_security(int W, int H) {
  int y0 = 86;

  /* Subtab: Uyarilar | Sistem Loglari */
  const char *stabs[] = {"Uyarilar", "Sistem Loglari"};
  int stx = 16;
  for (int i = 0; i < 2; i++) {
    int sw = MeasureText(stabs[i], 12) + 20;
    Rectangle sb = {stx, y0, sw, 22};
    int sh = CheckCollisionPointRec(GetMousePosition(), sb);
    if (i == g_security_subtab) {
      DrawRectangleRounded(sb, 0.4f, 4, COLOR_SELECTED);
      DrawTextC(stabs[i], stx + 10, y0 + 5, 12, COLOR_ACCENT);
    } else {
      if (sh)
        DrawRectangleRounded(sb, 0.4f, 4, (Color){255, 255, 255, 6});
      DrawTextC(stabs[i], stx + 10, y0 + 5, 12,
                sh ? COLOR_TEXT : COLOR_TEXT_SEC);
    }
    if (sh && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      g_security_subtab = i;
      g_scroll_alerts = 0;
      g_scroll_rawlog = 0;
    }
    stx += sw + 4;
  }

  int py = y0 + 28;

  if (g_security_subtab == 0) {
    /* === Uyarilar === */
    int cw = (W - 36) / 5;
    struct {
      const char *label;
      int *val;
      Color color;
    } cats[] = {
        {"Kritik", &g_analysis.critical, COLOR_RED},
        {"Yuksek", &g_analysis.high, COLOR_AMBER},
        {"Orta", &g_analysis.medium, (Color){234, 179, 8, 255}},
        {"Dusuk", &g_analysis.low, COLOR_GREEN},
        {"Bilgi", &g_analysis.info, COLOR_TEXT_SEC},
    };
    char nbuf[8];
    for (int i = 0; i < 5; i++) {
      snprintf(nbuf, sizeof(nbuf), "%d", *cats[i].val);
      draw_stat_card((Rectangle){12 + i * cw, py, cw - 4, 50}, cats[i].label,
                     nbuf, cats[i].color, NULL);
    }

    int panel_y = py + 58;
    DrawRoundedPanel((Rectangle){12, panel_y, W - 24, H - panel_y - 8},
                     COLOR_PANEL, COLOR_BORDER);
    char title[64];
    snprintf(title, sizeof(title), "Guvenlik Uyarilari (%d)",
             g_analysis.alert_count);
    DrawTextC(title, 24, panel_y + 8, 12, COLOR_ACCENT);

    Rectangle clr_btn = {W - 110, panel_y + 5, 80, 20};
    if (GuiButton(clr_btn, "Temizle")) {
      analyzer_clear_alerts();
      analyzer_run(&g_analysis);
    }

    if (g_analysis.alert_count == 0) {
      DrawTextC("Aktif uyari yok.", W / 2 - 60, H / 2, 14, COLOR_GREEN);
      return;
    }

    int item_h = 64;
    Rectangle area = {12, panel_y + 30, W - 24, H - panel_y - 42};
    if (CheckCollisionPointRec(GetMousePosition(), area)) {
      g_scroll_alerts -= GetMouseWheelMove() * 40;
      if (g_scroll_alerts < 0)
        g_scroll_alerts = 0;
      float mx = (g_analysis.alert_count * item_h) - area.height;
      if (mx < 0)
        mx = 0;
      if (g_scroll_alerts > mx)
        g_scroll_alerts = mx;
    }

    BeginScissorModeScaled(area.x, area.y, area.width, area.height);
    for (int i = 0; i < g_analysis.alert_count; i++) {
      int iy = area.y + i * item_h - (int)g_scroll_alerts;
      if (iy + item_h < area.y || iy > area.y + area.height)
        continue;
      Alert *a = &g_analysis.alerts[i];
      Rectangle ir = {area.x + 4, iy, area.width - 8, item_h - 3};

      Color bg = str_contains(a->severity, "KRITIK")   ? (Color){40, 8, 8, 255}
                 : str_contains(a->severity, "YUKSEK") ? (Color){35, 18, 6, 255}
                                                       : COLOR_SURFACE;
      DrawRectangleRounded(ir, 0.06f, 6, bg);

      Color sc = str_contains(a->severity, "KRITIK")   ? COLOR_RED
                 : str_contains(a->severity, "YUKSEK") ? COLOR_AMBER
                 : str_contains(a->severity, "ORTA") ? (Color){234, 179, 8, 255}
                                                     : COLOR_GREEN;
      DrawRectangle(ir.x, ir.y, 3, ir.height, sc);

      int slw = MeasureText(a->severity, 8) + 8;
      DrawRectangleRounded((Rectangle){ir.x + 8, ir.y + 5, slw, 12}, 0.5f, 4,
                           (Color){sc.r, sc.g, sc.b, 50});
      DrawTextC(a->severity, ir.x + 12, ir.y + 6, 8, sc);

      DrawTextC(a->title, ir.x + 12, ir.y + 20, 11, COLOR_TEXT);
      DrawTextC(a->description, ir.x + 12, ir.y + 34, 9, COLOR_TEXT_SEC);
      DrawTextC(a->recommendation, ir.x + 12, ir.y + 47, 9, COLOR_TEXT_DIM);
    }
    EndScissorMode();
  } else {
    /* === Sistem Loglari === */
    DrawRoundedPanel((Rectangle){12, py, W - 24, H - py - 8}, COLOR_PANEL,
                     COLOR_BORDER);
    DrawTextC("Sistem Log Analizi", 24, py + 8, 12, COLOR_ACCENT);

    const char *sources[] = {"journal", "httpd_access", "httpd_error",
                             "mariadb", "dmesg"};
    const char *labels[] = {"Journal", "HTTP", "Hatalar", "DB", "Kernel"};
    int bx = W - 420;
    for (int i = 0; i < 5; i++) {
      Rectangle b = {bx, py + 5, 76, 20};
      int active = (strcmp(g_raw_log_source, sources[i]) == 0);
      if (active)
        DrawRectangleRounded(b, 0.4f, 4, COLOR_SELECTED);
      int hover = CheckCollisionPointRec(GetMousePosition(), b);
      if (hover && !active)
        DrawRectangleRounded(b, 0.4f, 4, (Color){255, 255, 255, 6});
      DrawTextC(labels[i], bx + 6, py + 9, 10,
                active ? COLOR_ACCENT : (hover ? COLOR_TEXT : COLOR_TEXT_SEC));
      if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        strncpy(g_raw_log_source, sources[i], sizeof(g_raw_log_source));
        g_raw_log_count =
            analyzer_read_raw_log(g_raw_log_source, g_raw_log_lines, 200);
        g_scroll_rawlog = 0;
      }
      bx += 82;
    }

    Rectangle la = {16, py + 30, W - 32, H - py - 42};
    DrawRectangleRounded(la, 0.02f, 4, COLOR_TERMINAL_BG);

    if (CheckCollisionPointRec(GetMousePosition(), la)) {
      g_scroll_rawlog -= GetMouseWheelMove() * 40;
      if (g_scroll_rawlog < 0)
        g_scroll_rawlog = 0;
      float mx = g_raw_log_count * 13 - la.height;
      if (mx < 0)
        mx = 0;
      if (g_scroll_rawlog > mx)
        g_scroll_rawlog = mx;
    }

    char lc_info[32];
    snprintf(lc_info, sizeof(lc_info), "%d satir", g_raw_log_count);
    int liw = MeasureText(lc_info, 10);
    DrawTextC(lc_info, W - liw - 24, py + 10, 10, COLOR_TEXT_DIM);

    if (g_raw_log_count == 0) {
      DrawTextC("Log bulunamadi.", la.x + 20, la.y + la.height / 2, 12,
                COLOR_TEXT_SEC);
    }

    BeginScissorModeScaled(la.x, la.y, la.width, la.height);
    for (int i = 0; i < g_raw_log_count; i++) {
      int ly = la.y + 4 + i * 13 - (int)g_scroll_rawlog;
      if (ly + 13 < la.y || ly > la.y + la.height)
        continue;
      Color lcolor = str_contains_ci(g_raw_log_lines[i], "error") ||
                             str_contains_ci(g_raw_log_lines[i], "crit")
                         ? COLOR_RED
                     : str_contains_ci(g_raw_log_lines[i], "warn") ? COLOR_AMBER
                     : str_contains_ci(g_raw_log_lines[i], "failed") ||
                             str_contains_ci(g_raw_log_lines[i], "denied")
                         ? (Color){245, 158, 100, 255}
                         : COLOR_TEXT_DIM;
      DrawText(g_raw_log_lines[i], la.x + 8, ly, 10, lcolor);
    }
    EndScissorMode();
  }
}

/* ========== Araclar Paneli (Port Scan + Brute Force) ========== */
static BfState g_bf_state;
static int g_bf_proto_sel = 5; /* BfProtocol enum index: 5=SSH */
static char g_bf_target[MAX_IP_LEN] = {0};
static int g_bf_port_override = 0; /* 0 = varsayilan port */
static int g_bf_threads = 10;
static float g_scroll_bf_results = 0;

static void draw_panel_tools(int W, int H) {
  int y0 = 86;

  /* Subtabs */
  const char *stabs[] = {"Port Tarayici", "Brute Force"};
  int stx = 16;
  for (int i = 0; i < 2; i++) {
    int sw = MeasureText(stabs[i], 12) + 20;
    Rectangle sb = {stx, y0, sw, 22};
    int sh = CheckCollisionPointRec(GetMousePosition(), sb);
    if (i == g_tools_subtab) {
      DrawRectangleRounded(sb, 0.4f, 4, COLOR_SELECTED);
      DrawTextC(stabs[i], stx + 10, y0 + 5, 12, COLOR_ACCENT);
    } else {
      if (sh)
        DrawRectangleRounded(sb, 0.4f, 4, (Color){255, 255, 255, 6});
      DrawTextC(stabs[i], stx + 10, y0 + 5, 12,
                sh ? COLOR_TEXT : COLOR_TEXT_SEC);
    }
    if (sh && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      g_tools_subtab = i;
    }
    stx += sw + 4;
  }

  int py = y0 + 32;
  int panel_h = H - py - 12;
  char buf[256];

  if (g_tools_subtab == 0) {
    /* === Port Tarayici === */
    int ctrl_w = 260;
    int result_w = W - 24 - ctrl_w - 8;

    /* --- Sol panel: Kontroller --- */
    DrawRoundedPanel((Rectangle){12, py, ctrl_w, panel_h}, COLOR_PANEL,
                     COLOR_BORDER);
    DrawTextC("Port Tarayici", 24, py + 8, 13, COLOR_ACCENT);

    portscan_get_results(&g_portscan);
    int is_this =
        (g_bf_target[0] && strcmp(g_portscan.target_ip, g_bf_target) == 0);
    int scanning = (is_this && g_portscan.is_scanning);

    int cy = py + 28;

    /* --- Hedef IP secimi (scrollable liste) --- */
    DrawTextC("Hedef:", 24, cy, 10, COLOR_TEXT_SEC);
    if (g_bf_target[0]) {
      DrawRectangleRounded(
          (Rectangle){64, cy - 2, MeasureText(g_bf_target, 10) + 10, 14}, 0.4f,
          4, COLOR_SELECTED);
      DrawTextC(g_bf_target, 69, cy, 10, COLOR_ACCENT);
    }
    cy += 16;

    int ip_list_h = 80;
    Rectangle ip_area = {20, cy, ctrl_w - 28, ip_list_h};
    DrawRectangleRounded(ip_area, 0.04f, 4, COLOR_SURFACE);
    int item_h = 20;
    float ip_max_scroll = g_scan.device_count * item_h - ip_list_h;
    if (ip_max_scroll < 0)
      ip_max_scroll = 0;
    if (CheckCollisionPointRec(GetMousePosition(), ip_area)) {
      g_scroll_ps_devices -= GetMouseWheelMove() * 20;
      if (g_scroll_ps_devices < 0)
        g_scroll_ps_devices = 0;
      if (g_scroll_ps_devices > ip_max_scroll)
        g_scroll_ps_devices = ip_max_scroll;
    }
    BeginScissorModeScaled(ip_area.x, ip_area.y, ip_area.width, ip_area.height);
    for (int i = 0; i < g_scan.device_count; i++) {
      int iy = cy + i * item_h - (int)g_scroll_ps_devices;
      if (iy + item_h < cy || iy > cy + ip_list_h)
        continue;
      Rectangle db = {22, iy + 1, ctrl_w - 44, item_h - 2};
      int sel = (strcmp(g_bf_target, g_scan.devices[i].ip) == 0);
      int hov = CheckCollisionPointRec(GetMousePosition(), db);
      if (sel)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_PANEL_HOVER);
      if (sel)
        DrawRectangle(db.x, db.y + 3, 3, db.height - 6, COLOR_ACCENT);
      DrawTextC(g_scan.devices[i].ip, db.x + 10, db.y + 4, 10,
                sel ? COLOR_ACCENT : COLOR_TEXT);
      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        strncpy(g_bf_target, g_scan.devices[i].ip, MAX_IP_LEN - 1);
    }
    EndScissorMode();
    draw_custom_scrollbar(ip_area.x + ip_area.width - 10, ip_area.y, 10,
                          ip_list_h, g_scan.device_count * item_h,
                          &g_scroll_ps_devices);
    cy += ip_list_h + 8;

    DrawRectangle(24, cy, ctrl_w - 40, 1, COLOR_BORDER);
    cy += 8;

    /* --- Tarama butonlari --- */
    if (g_bf_target[0] == '\0') {
      DrawTextC("Bir hedef IP secin.", 24, cy + 4, 11, COLOR_TEXT_DIM);
    } else if (!scanning) {
      DrawTextC("Tarama Baslat:", 24, cy, 10, COLOR_TEXT_SEC);
      cy += 16;
      int bw = (ctrl_w - 56) / 2;
      if (GuiButton((Rectangle){24, cy, bw, 26}, "Top Portlar"))
        portscan_start_top(g_bf_target, PS_SCAN_CONNECT);
      if (GuiButton((Rectangle){28 + bw, cy, bw, 26}, "1 - 1024"))
        portscan_start(g_bf_target, PS_SCAN_CONNECT, 1, 1024);
      cy += 30;
      if (GuiButton((Rectangle){24, cy, bw, 26}, "1 - 10000"))
        portscan_start(g_bf_target, PS_SCAN_CONNECT, 1, 10000);
      if (GuiButton((Rectangle){28 + bw, cy, bw, 26}, "Tam (65535)"))
        portscan_start(g_bf_target, PS_SCAN_CONNECT, 1, 65535);
      cy += 34;
    } else {
      /* Progress bar */
      int target = g_portscan.total_target_ports > 0
                       ? g_portscan.total_target_ports
                       : 100;
      float prog = (float)g_portscan.total_scanned / (float)target;
      if (prog > 1.0f)
        prog = 1.0f;
      int pbar_w = ctrl_w - 48;

      DrawTextC("Tarama devam ediyor...", 24, cy, 10, COLOR_AMBER);
      cy += 14;
      DrawRectangleRounded((Rectangle){24, cy, pbar_w, 18}, 0.5f, 4,
                           (Color){20, 28, 48, 255});
      if (prog > 0.005f)
        DrawRectangleRounded((Rectangle){24, cy, pbar_w * prog, 18}, 0.5f, 4,
                             COLOR_ACCENT);
      snprintf(buf, sizeof(buf), "%d / %d  (%.0f%%)", g_portscan.total_scanned,
               target, prog * 100);
      DrawTextC(buf, 30, cy + 4, 9, COLOR_TEXT);
      cy += 22;
      if (GuiButton((Rectangle){24, cy, pbar_w, 22}, "Durdur"))
        portscan_stop();
      cy += 28;
    }

    DrawRectangle(24, cy, ctrl_w - 40, 1, COLOR_BORDER);
    cy += 8;

    /* --- Sonuc ozeti --- */
    if (is_this && (g_portscan.open_count > 0 || g_portscan.scan_complete)) {
      snprintf(buf, sizeof(buf), "Acik: %d", g_portscan.open_count);
      DrawTextC(buf, 24, cy, 12, COLOR_GREEN);
      cy += 16;
      snprintf(buf, sizeof(buf), "Filtrelenmis: %d", g_portscan.filtered_count);
      DrawTextC(buf, 24, cy, 10, COLOR_AMBER);
      cy += 13;
      snprintf(buf, sizeof(buf), "Taranan: %d / Sure: %.1fs",
               g_portscan.total_scanned, g_portscan.scan_time_sec);
      DrawTextC(buf, 24, cy, 10, COLOR_TEXT_SEC);
      cy += 13;
      if (g_portscan.os_guess[0]) {
        snprintf(buf, sizeof(buf), "OS: %s (%d%%)", g_portscan.os_guess,
                 g_portscan.os_confidence);
        DrawTextC(buf, 24, cy, 10, COLOR_CYAN);
        cy += 13;
      }
      if (g_portscan.total_vulns_found > 0) {
        snprintf(buf, sizeof(buf), "Zafiyet: %d", g_portscan.total_vulns_found);
        DrawTextC(buf, 24, cy, 10, COLOR_RED);
      }
    } else if (!is_this && !scanning) {
      DrawTextC("Sonuc yok.", 24, cy, 10, COLOR_TEXT_DIM);
    }

    /* --- Sag panel: Sonuc tablosu --- */
    int rx = 12 + ctrl_w + 8;
    DrawRoundedPanel((Rectangle){rx, py, result_w, panel_h}, COLOR_PANEL,
                     COLOR_BORDER);
    DrawTextC("Tarama Sonuclari", rx + 12, py + 8, 13, COLOR_ACCENT);

    if (is_this && g_bf_target[0]) {
      snprintf(buf, sizeof(buf), "%s", g_bf_target);
      int bw2 = MeasureText(buf, 9);
      DrawTextC(buf, rx + result_w - bw2 - 12, py + 10, 9, COLOR_TEXT_DIM);
    }

    /* Tablo basligi */
    int hdr_y = py + 28;
    DrawRectangle(rx + 4, hdr_y, result_w - 8, 18, COLOR_SURFACE);
    DrawTextC("Port", rx + 10, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Durum", rx + 60, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Servis", rx + 120, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Urun/Versiyon", rx + 200, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Vuln", rx + result_w - 140, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("SSL", rx + result_w - 100, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("RTT", rx + result_w - 60, hdr_y + 4, 9, COLOR_TEXT_SEC);

    int list_y0 = hdr_y + 20;
    int list_h = panel_h - (list_y0 - py) - 4;

    if (!is_this || (g_portscan.open_count == 0 && !g_portscan.scan_complete)) {
      const char *msg =
          scanning ? "Tarama devam ediyor..." : "Tarama baslatilmadi.";
      int mw = MeasureText(msg, 12);
      DrawTextC(msg, rx + result_w / 2 - mw / 2, py + panel_h / 2, 12,
                COLOR_TEXT_SEC);
    } else if (g_portscan.open_count == 0 && g_portscan.scan_complete) {
      DrawTextC("Acik port bulunamadi.", rx + result_w / 2 - 70,
                py + panel_h / 2, 12, COLOR_GREEN);
    } else {
      /* Row height: normal=22, expanded vuln=22 + vuln_count*14 + 8 */
      /* Hesapla toplam yukseklik */
      int total_h = 0;
      for (int i = 0; i < g_portscan.open_count; i++) {
        total_h += 22;
        if (g_ps_selected_vuln_port == g_portscan.ports[i].port &&
            g_portscan.ports[i].vuln_count > 0)
          total_h += g_portscan.ports[i].vuln_count * 16 + 8;
      }
      float ms = total_h - list_h;
      if (ms < 0)
        ms = 0;
      Rectangle la = {rx, list_y0, result_w, list_h};
      if (CheckCollisionPointRec(GetMousePosition(), la)) {
        g_scroll_tool_ports -= GetMouseWheelMove() * 30;
        if (g_scroll_tool_ports < 0)
          g_scroll_tool_ports = 0;
        if (g_scroll_tool_ports > ms)
          g_scroll_tool_ports = ms;
      }

      BeginScissorModeScaled(rx, list_y0, result_w, list_h);
      int ry2 = list_y0 - (int)g_scroll_tool_ports;
      for (int i = 0; i < g_portscan.open_count; i++) {
        PortResult *pr = &g_portscan.ports[i];
        if (ry2 > list_y0 + list_h)
          break;

        int row_h = 22;
        int expanded =
            (g_ps_selected_vuln_port == pr->port && pr->vuln_count > 0);
        if (expanded)
          row_h += pr->vuln_count * 16 + 8;

        if (ry2 + row_h >= list_y0) {
          /* Ana satir */
          Rectangle rr = {rx + 4, ry2, result_w - 24, 21};
          int hov = CheckCollisionPointRec(GetMousePosition(), rr);
          Color rbg = (i % 2 == 0) ? (Color){14, 20, 36, 255} : COLOR_SURFACE;
          if (hov)
            rbg = COLOR_PANEL_HOVER;
          DrawRectangleRec(rr, rbg);

          /* Vuln sidebar */
          if (pr->vuln_count > 0) {
            Color vc = COLOR_AMBER;
            for (int v = 0; v < pr->vuln_count; v++)
              if (strcmp(pr->vulns[v].severity, "CRITICAL") == 0) {
                vc = COLOR_RED;
                break;
              }
            DrawRectangle(rx + 4, ry2, 3, 21, vc);
          }

          char pb[16];
          snprintf(pb, sizeof(pb), "%d", pr->port);
          DrawTextC(pb, rx + 10, ry2 + 5, 10, COLOR_TEXT);

          const char *status_str = pr->status == PORT_OPEN       ? "open"
                                   : pr->status == PORT_FILTERED ? "filtered"
                                                                 : "open|flt";
          Color stc = pr->status == PORT_OPEN ? COLOR_GREEN : COLOR_AMBER;
          DrawTextC(status_str, rx + 60, ry2 + 5, 10, stc);

          int danger = (pr->port == 4444 || pr->port == 5555 ||
                        pr->port == 31337 || pr->port == 6667);
          DrawTextC(pr->service, rx + 120, ry2 + 5, 10,
                    danger ? COLOR_RED : COLOR_CYAN);

          /* Product/version */
          char pv[80];
          if (pr->product[0] && pr->version[0])
            snprintf(pv, sizeof(pv), "%.30s %.15s", pr->product, pr->version);
          else if (pr->product[0])
            snprintf(pv, sizeof(pv), "%.45s", pr->product);
          else
            pv[0] = '\0';
          DrawTextC(pv, rx + 200, ry2 + 5, 9, COLOR_TEXT_DIM);

          /* Vuln count badge */
          if (pr->vuln_count > 0) {
            snprintf(pb, sizeof(pb), "%d", pr->vuln_count);
            int bww = MeasureText(pb, 9) + 10;
            Color bc = COLOR_AMBER;
            for (int v = 0; v < pr->vuln_count; v++)
              if (strcmp(pr->vulns[v].severity, "CRITICAL") == 0) {
                bc = COLOR_RED;
                break;
              }
            DrawRectangleRounded(
                (Rectangle){rx + result_w - 144, ry2 + 4, bww, 14}, 0.5f, 4,
                (Color){bc.r, bc.g, bc.b, 60});
            DrawTextC(pb, rx + result_w - 140, ry2 + 5, 9, bc);
          }

          /* SSL badge */
          if (pr->is_ssl)
            DrawTextC("TLS", rx + result_w - 96, ry2 + 5, 9, COLOR_GREEN);

          snprintf(pb, sizeof(pb), "%.0fms", pr->rtt_ms);
          DrawTextC(pb, rx + result_w - 56, ry2 + 5, 9, COLOR_TEXT_SEC);

          /* Click to expand vulns */
          if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT) &&
              pr->vuln_count > 0) {
            if (g_ps_selected_vuln_port == pr->port)
              g_ps_selected_vuln_port = -1;
            else
              g_ps_selected_vuln_port = pr->port;
          }

          /* Expanded vuln detail */
          if (expanded) {
            int vy = ry2 + 24;
            for (int v = 0; v < pr->vuln_count; v++) {
              VulnerabilityNote *vn = &pr->vulns[v];
              Color sc2 = strcmp(vn->severity, "CRITICAL") == 0 ? COLOR_RED
                          : strcmp(vn->severity, "HIGH") == 0
                              ? COLOR_AMBER
                              : (Color){234, 179, 8, 255};
              DrawRectangle(rx + 20, vy, result_w - 28, 15,
                            (Color){sc2.r / 6, sc2.g / 6, sc2.b / 6, 255});
              DrawRectangle(rx + 20, vy, 2, 15, sc2);

              int svw = MeasureText(vn->severity, 8) + 6;
              DrawRectangleRounded((Rectangle){rx + 26, vy + 2, svw, 11}, 0.5f,
                                   4, (Color){sc2.r, sc2.g, sc2.b, 40});
              DrawTextC(vn->severity, rx + 29, vy + 3, 8, sc2);
              DrawTextC(vn->cve_id, rx + 30 + svw, vy + 3, 8, COLOR_TEXT);

              char desc_short[80];
              strncpy(desc_short, vn->description, 79);
              desc_short[79] = '\0';
              DrawTextC(desc_short,
                        rx + 30 + svw + MeasureText(vn->cve_id, 8) + 8, vy + 3,
                        8, COLOR_TEXT_DIM);
              vy += 16;
            }
          }
        }
        ry2 += row_h;
      }
      EndScissorMode();
      draw_custom_scrollbar(rx + result_w - 10, list_y0, 10, list_h, total_h,
                            &g_scroll_tool_ports);
    }
  } else {
    /* === Brute Force === */
    bf_get_state(&g_bf_state);
    int cw = (W - 36) / 4;

    snprintf(buf, sizeof(buf), "%d/%d", g_bf_state.tested_combos,
             g_bf_state.total_combos);
    draw_stat_card((Rectangle){12, py, cw - 4, 66}, "Ilerleme", buf,
                   g_bf_state.is_running ? COLOR_AMBER : COLOR_ACCENT,
                   g_bf_state.is_running ? "Tarama devam ediyor" : "Hazir");

    snprintf(buf, sizeof(buf), "%d", g_bf_state.result_count);
    draw_stat_card((Rectangle){12 + cw, py, cw - 4, 66}, "Bulunan", buf,
                   g_bf_state.result_count > 0 ? COLOR_RED : COLOR_GREEN,
                   g_bf_state.result_count > 0 ? "Zayif Kimlik!" : "Temiz");

    snprintf(buf, sizeof(buf), "%.1fs", g_bf_state.elapsed_sec);
    draw_stat_card((Rectangle){12 + cw * 2, py, cw - 4, 66}, "Sure", buf,
                   COLOR_ACCENT2, "Gecen sure");

    snprintf(buf, sizeof(buf), "%d", g_bf_state.thread_count);
    draw_stat_card((Rectangle){12 + cw * 3, py, cw - 4, 66}, "Thread", buf,
                   COLOR_TEXT, "Paralel islem");

    py += 74;
    panel_h = H - py - 12;

    int ctrl_w = 340;
    int result_w = W - 24 - ctrl_w - 8;

    /* --- Sol panel: Kontroller --- */
    DrawRoundedPanel((Rectangle){12, py, ctrl_w, panel_h}, COLOR_PANEL,
                     COLOR_BORDER);
    DrawTextC("Saldiri Ayarlari", 24, py + 8, 13, COLOR_ACCENT);

    int cy = py + 32;

    /* --- Hedef IP secimi (scrollable liste) --- */
    DrawTextC("Hedef:", 24, cy, 10, COLOR_TEXT_SEC);
    if (g_bf_target[0]) {
      DrawRectangleRounded(
          (Rectangle){64, cy - 2, MeasureText(g_bf_target, 10) + 10, 14}, 0.4f,
          4, COLOR_SELECTED);
      DrawTextC(g_bf_target, 69, cy, 10, COLOR_ACCENT);
    }
    cy += 16;

    int ip_list_h = 80;
    Rectangle ip_area = {20, cy, ctrl_w - 28, ip_list_h};
    DrawRectangleRounded(ip_area, 0.04f, 4, COLOR_SURFACE);
    int item_h = 20;
    float ip_max_scroll = g_scan.device_count * item_h - ip_list_h;
    if (ip_max_scroll < 0)
      ip_max_scroll = 0;
    if (CheckCollisionPointRec(GetMousePosition(), ip_area)) {
      g_scroll_bf_devices -= GetMouseWheelMove() * 20;
      if (g_scroll_bf_devices < 0)
        g_scroll_bf_devices = 0;
      if (g_scroll_bf_devices > ip_max_scroll)
        g_scroll_bf_devices = ip_max_scroll;
    }
    BeginScissorModeScaled(ip_area.x, ip_area.y, ip_area.width, ip_area.height);
    for (int i = 0; i < g_scan.device_count; i++) {
      int iy = cy + i * item_h - (int)g_scroll_bf_devices;
      if (iy + item_h < cy || iy > cy + ip_list_h)
        continue;
      Rectangle db = {22, iy + 1, ctrl_w - 44, item_h - 2};
      int sel = (strcmp(g_bf_target, g_scan.devices[i].ip) == 0);
      int hov = CheckCollisionPointRec(GetMousePosition(), db);
      if (sel)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_PANEL_HOVER);
      if (sel)
        DrawRectangle(db.x, db.y + 3, 3, db.height - 6, COLOR_ACCENT);
      DrawTextC(g_scan.devices[i].ip, db.x + 10, db.y + 4, 10,
                sel ? COLOR_ACCENT : COLOR_TEXT);
      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        strncpy(g_bf_target, g_scan.devices[i].ip, MAX_IP_LEN - 1);
    }
    EndScissorMode();
    draw_custom_scrollbar(ip_area.x + ip_area.width - 10, ip_area.y, 10,
                          ip_list_h, g_scan.device_count * item_h,
                          &g_scroll_bf_devices);
    cy += ip_list_h + 8;

    DrawRectangle(24, cy, ctrl_w - 40, 1, COLOR_BORDER);
    cy += 12;

    /* Protokol Secimi — BfProtocol enum sirasina gore */
    DrawTextC("Protokol:", 24, cy, 11, COLOR_TEXT_SEC);
    cy += 16;
    /* BF_PROTO_FTP=0, HTTP_POST=1, HTTP_GET=2, MYSQL=3, TELNET=4, SSH=5, SMB=6,
     * RDP=7 */
    const char *proto_labels[] = {"FTP",    "HTTP-P", "HTTP-G", "MySQL",
                                  "Telnet", "SSH",    "SMB",    "RDP"};
    for (int i = 0; i < 8; i++) {
      int bx = 24 + (i % 4) * 76;
      int by = cy + (i / 4) * 24;
      Rectangle pb = {bx, by, 72, 20};
      int sel = (g_bf_proto_sel == i);
      int hover = CheckCollisionPointRec(GetMousePosition(), pb);
      Color bg = sel ? COLOR_SELECTED
                     : (hover ? COLOR_PANEL_HOVER : (Color){20, 28, 48, 255});
      DrawRectangleRounded(pb, 0.3f, 4, bg);
      if (sel)
        DrawRectangle(bx, by + 18, 72, 2, COLOR_ACCENT);
      DrawTextC(proto_labels[i], bx + 4, by + 5, 9,
                sel ? COLOR_ACCENT : COLOR_TEXT_DIM);
      if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        g_bf_proto_sel = i;
    }
    cy += 54;

    /* Thread Sayisi (Basit slider efekti) */
    DrawTextC("Thread:", 24, cy, 11, COLOR_TEXT_SEC);
    cy += 16;
    Rectangle slider_rect = {24, cy, ctrl_w - 40, 16};
    int hover_slider = CheckCollisionPointRec(GetMousePosition(), slider_rect);
    if (hover_slider && IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
      float pct = (GetMousePosition().x - 24) / (float)(ctrl_w - 40);
      g_bf_threads = 1 + (int)(pct * 49); /* 1-50 thread */
      if (g_bf_threads < 1)
        g_bf_threads = 1;
      if (g_bf_threads > 50)
        g_bf_threads = 50;
    }
    float pct = (g_bf_threads - 1) / 49.0f;
    DrawRectangleRounded((Rectangle){24, cy, ctrl_w - 40, 12}, 0.5f, 4,
                         (Color){20, 28, 48, 255});
    DrawRectangleRounded((Rectangle){24, cy, (ctrl_w - 40) * pct, 12}, 0.5f, 4,
                         COLOR_ACCENT);
    snprintf(buf, sizeof(buf), "%d thread", g_bf_threads);
    DrawTextC(buf, 24 + ctrl_w / 2 - 20, cy + 1, 9, COLOR_TEXT);
    cy += 32;

    /* Baslat/Durdur Butonu */
    Rectangle btn = {24, cy, ctrl_w - 40, 36};
    if (!g_bf_state.is_running) {
      if (GuiButton(btn, "Saldiriyi Baslat")) {
        if (g_bf_target[0] != '\0') {
          bf_start(g_bf_target, g_bf_port_override, (BfProtocol)g_bf_proto_sel,
                   g_bf_threads);
        } else {
          /* Hedef secilmedi uyarisi */
          DrawTextC("Once bir hedef IP secin!", 24, cy + 8, 11, COLOR_AMBER);
        }
      }
    } else {
      if (GuiButton(btn, "Saldiriyi Durdur"))
        bf_stop();
    }

    /* --- Sag panel: Sonuclar --- */
    int rx = 12 + ctrl_w + 8;
    DrawRoundedPanel((Rectangle){rx, py, result_w, panel_h}, COLOR_PANEL,
                     COLOR_BORDER);
    DrawTextC("Sonuclar", rx + 12, py + 8, 13, COLOR_ACCENT);

    if (g_bf_state.target_ip[0]) {
      snprintf(buf, sizeof(buf), "%s:%d [%s]", g_bf_state.target_ip,
               g_bf_state.port, bf_proto_name(g_bf_state.protocol));
      int bw = MeasureText(buf, 10);
      DrawTextC(buf, rx + result_w - bw - 12, py + 10, 10, COLOR_TEXT_DIM);
    }

    /* Baslik satiri */
    int hdr_y = py + 30;
    DrawRectangle(rx + 4, hdr_y + 16, result_w - 8, 1, COLOR_BORDER);
    DrawTextC("#", rx + 12, hdr_y + 3, 10, COLOR_TEXT_SEC);
    DrawTextC("Kullanici", rx + 36, hdr_y + 3, 10, COLOR_TEXT_SEC);
    DrawTextC("Parola", rx + result_w / 2 - 40, hdr_y + 3, 10, COLOR_TEXT_SEC);
    DrawTextC("Sure", rx + result_w - 80, hdr_y + 3, 10, COLOR_TEXT_SEC);

    if (g_bf_state.result_count == 0) {
      const char *msg = g_bf_state.is_complete  ? "Zayif kimlik bulunamadi."
                        : g_bf_state.is_running ? "Tarama devam ediyor..."
                                                : "Saldiri baslatilmadi.";
      Color mc = g_bf_state.is_complete ? COLOR_GREEN : COLOR_TEXT_SEC;
      int mw = MeasureText(msg, 12);
      DrawTextC(msg, rx + result_w / 2 - mw / 2, py + panel_h / 2, 12, mc);
    } else {
      int item_h = 36;
      int list_start = hdr_y + 20;
      int list_h = panel_h - (list_start - py) - 8;

      float max_s = g_bf_state.result_count * item_h - list_h;
      if (max_s < 0)
        max_s = 0;
      Rectangle res_area = {rx, list_start, result_w, list_h};
      if (CheckCollisionPointRec(GetMousePosition(), res_area)) {
        g_scroll_bf_results -= GetMouseWheelMove() * 30;
        if (g_scroll_bf_results < 0)
          g_scroll_bf_results = 0;
        if (g_scroll_bf_results > max_s)
          g_scroll_bf_results = max_s;
      }

      BeginScissorModeScaled(rx, list_start, result_w, list_h);
      for (int i = 0; i < g_bf_state.result_count; i++) {
        int iy = list_start + i * item_h - (int)g_scroll_bf_results;
        if (iy + item_h < list_start || iy > list_start + list_h)
          continue;
        BfCredResult *cr = &g_bf_state.results[i];

        Color row_bg = (Color){50, 10, 10, 255};
        DrawRectangle(rx + 4, iy, result_w - 8, item_h - 2, row_bg);
        DrawRectangle(rx + 4, iy, 3, item_h - 2, COLOR_RED);

        snprintf(buf, sizeof(buf), "%d", i + 1);
        DrawTextC(buf, rx + 12, iy + 8, 11, COLOR_TEXT_SEC);
        DrawTextC(cr->username, rx + 36, iy + 4, 12, COLOR_RED);
        DrawTextC(cr->password, rx + result_w / 2 - 40, iy + 4, 12,
                  COLOR_AMBER);

        snprintf(buf, sizeof(buf), "%.0fms", cr->time_ms);
        DrawTextC(buf, rx + result_w - 80, iy + 8, 10, COLOR_TEXT_DIM);

        /* TEHLIKE badge */
        DrawRectangleRounded((Rectangle){rx + 36, iy + 18, 50, 12}, 0.5f, 4,
                             (Color){180, 30, 30, 180});
        DrawTextC("KIRILDI!", rx + 39, iy + 19, 8, (Color){255, 200, 200, 255});
      }
      EndScissorMode();
    }
  }
}

/* ========== Public API ========== */
void gui_init(int width, int height) {
  (void)width;
  (void)height;

  /* Pencere: boyutlandırılabilir + MSAA */
  SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_MSAA_4X_HINT);
  InitWindow(1280, 720, "CySec");

  /* FLAG_WINDOW_MAXIMIZED bayrağı bazı Windows ortamlarında çalışmıyor.
   * Açıkça MaximizeWindow() çağırarak pencereyi maximize ediyoruz. */
  MaximizeWindow();
  SetWindowMinSize(800, 600);

  SetTargetFPS(30);

  /* raygui style */
  GuiSetStyle(DEFAULT, TEXT_SIZE, 12);
  GuiSetStyle(DEFAULT, BACKGROUND_COLOR, ColorToInt(COLOR_PANEL));
  GuiSetStyle(BUTTON, BASE_COLOR_NORMAL, ColorToInt((Color){30, 40, 65, 255}));
  GuiSetStyle(BUTTON, TEXT_COLOR_NORMAL, ColorToInt(COLOR_ACCENT));
  GuiSetStyle(BUTTON, BORDER_COLOR_NORMAL, ColorToInt(COLOR_BORDER));

  /* TTF Font yükle ve yapılandır */
  g_custom_font = LoadFontEx("../assets/fonts/Roboto-Regular.ttf", 64, 0, 250);
  if (g_custom_font.texture.id > 0) {
    SetTextureFilter(g_custom_font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(g_custom_font);
  }

  /* İlk log yükle */
  g_raw_log_count = analyzer_read_raw_log("journal", g_raw_log_lines, 200);
}

void gui_cleanup(void) {
  if (g_custom_font.texture.id > 0)
    UnloadFont(g_custom_font);
  CloseWindow();
}

int gui_should_close(void) { return WindowShouldClose(); }

void gui_draw(void) {
  int monitor = GetCurrentMonitor();
  int m_height = GetMonitorHeight(monitor);
  if (m_height <= 0) m_height = GetScreenHeight();

  // Monitör çözünürlüğüne göre ölçek (720p -> 1.0, 1080p -> 1.5, 2K -> 2.0, 4K -> 3.0)
  // Text'lerin küçük kalmaması için native DPI tarzı ölçekleme
  g_ui_scale = (float)m_height / 720.0f;
  if (g_ui_scale < 0.8f) g_ui_scale = 0.8f;

  int W = GetScreenWidth();
  int H = GetScreenHeight();

  // Mantıksal (Logical) ekran boyutunu hesapla
  int V_WIDTH = (int)(W / g_ui_scale);
  int V_HEIGHT = (int)(H / g_ui_scale);

  // Mouse koordinatlarını logical koordinatlara çevir
  SetMouseScale(1.0f / g_ui_scale, 1.0f / g_ui_scale);
  SetMouseOffset(0, 0);

  /* Periyodik veri yenileme (her 2 saniye) */
  double now = GetTime();
  if (now - g_last_refresh > 2.0) {
    scanner_get_results(&g_scan);
    scanner_get_log(&g_scanlog);
    analyzer_run(&g_analysis);
    g_last_refresh = now;
  }

  BeginDrawing();
  ClearBackground(COLOR_BG);

  // Vektörel zoom işlemini uygulayan kamera
  Camera2D camera = { 0 };
  camera.zoom = g_ui_scale;
  BeginMode2D(camera);

  // Bütün çizimleri logical boyutlarda yap
  draw_header(V_WIDTH);
  draw_tabs(V_WIDTH);

  switch (g_active_tab) {
  case TAB_DASHBOARD:
    draw_panel_dashboard(V_WIDTH, V_HEIGHT);
    break;
  case TAB_SECURITY:
    draw_panel_security(V_WIDTH, V_HEIGHT);
    break;
  case TAB_TOOLS:
    draw_panel_tools(V_WIDTH, V_HEIGHT);
    break;
  default:
    break;
  }

  EndMode2D();
  EndDrawing();

  // Input state reset (sistem diğer elemanları etkilemesin diye)
  SetMouseScale(1, 1);
}

void gui_select_device(const char *ip) {
  strncpy(g_selected_device_ip, ip, MAX_IP_LEN - 1);
  g_scroll_device_detail = 0;
}
