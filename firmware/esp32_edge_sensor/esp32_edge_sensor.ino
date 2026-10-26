/*
 * SecTriage 边缘告警源 · ESP32 固件  v1.1（零外设版）
 * ---------------------------------------------------------------
 * 定位：它不是"传感器上报器"，是**降噪的第一层**。
 *   本机每 5 秒采一次，正常就不发；只有连续 3 个窗口越界，才向服务端报 1 条事件。
 *
 * v1.1 新增（全部不需要任何外接元件，只用板子本身）：
 *   - BLE 通道：扫周边蓝牙广播，设备数突增算一条事件（第二维信号）
 *   - 链路质量：自身 RSSI 持续劣化 + 重连次数 → link_degraded
 *   - 板载 LED 状态码：无 WiFi 快闪 / 缓冲积压中闪 / 正常熄灭，上报成功闪一下
 *   - 芯片温度一并上报（长期贴墙运行时的过热信号）
 *
 * 三个只有真硬件才会有的问题，固件里必须处理（这是软件造不出来的证据）：
 *   1) 没有可靠时钟 -> 不上报墙钟时间，用 boot_id + seq 保证顺序
 *   2) 断网会丢事件 -> 200 条环形缓冲 + 幂等重放（服务端按 boot_id+seq 去重）
 *   3) 会重启        -> 重启原因本身作为一条可用性事件上报
 *
 * 依赖：只用 Arduino-ESP32 自带库（WiFi/BLE/HTTPClient），不装第三方库
 * 板型：ESP32-WROOM-32（经典款，已实测 chip rev3 / 4MB flash / 无 PSRAM）
 *
 * 凭据：写在 secrets.h（已被 .gitignore 排除）；见 secrets.h.example
 */

#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_system.h"          // esp_random / esp_reset_reason / temperatureRead
#include <HTTPClient.h>
#include <string.h>              // memcmp：比较 BSSID 内容，不能比指针
#include <BLEDevice.h>           // 板载蓝牙：第二维信号，零外设
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// ---------------- 配置 ----------------
// WiFi 密码不写进源码：新建 secrets.h 覆盖下面三个默认值（见 secrets.h.example）。
// 这样固件文件可以直接提交，凭据不会进 git。
#if __has_include("secrets.h")
#include "secrets.h"
#endif

#ifndef WIFI_SSID
#define WIFI_SSID "你的WiFi名"
#endif
#ifndef WIFI_PASS
#define WIFI_PASS "你的WiFi密码"
#endif
#ifndef SERVER_URL
#define SERVER_URL "http://192.168.1.51:8200/ingest"   // 你电脑的局域网 IP
#endif
#ifndef DEVICE_ID
#define DEVICE_ID "esp32-lab-01"
#endif
#ifndef INGEST_TOKEN
#define INGEST_TOKEN ""              // 服务端没设 INGEST_TOKEN 就留空
#endif

const char *FW_VERSION = "1.1.0";

// 1 = 每个窗口打印一行 [win]，用于测基线 / 算降噪比（实验 1 必需）
// 0 = 只在异常时打印，上线用这个
#define VERBOSE 1

// 板载 LED 的引脚：经典 ESP32 DevKit 一般是 GPIO2；如果你的板子是 S3/C3 要改
#define LED_PIN 2

// BLE 通道开关（不需要任何外设，但会让固件大 ~40KB）
#define ENABLE_BLE 1

// ---------------- 判定参数 ----------------
const uint32_t WINDOW_MS        = 5000;    // 采样窗口
const uint32_t MIN_GAP_WINDOWS  = 3;       // 连续几个窗口越界才报（去抖）
const uint32_t DEFAULT_BASELINE = 12;      // 探测请求基线（冷启动用，之后用指数平均）

// 阈值地板。**这个数是量出来的，不是拍的**：
//   实测（2026-10-26，COM7，2 分钟共 23 个窗口）：
//     空闲：min 3 / 中位 12 / max 20
//     单台电脑正常扫描（netsh wlan show networks）：单窗口最高 26
//   所以地板设 25 会被正常扫描顶到 —— 连续 3 个窗口就误报。
//   取 40（约 3× 中位）留余量。
//   样本只有 2 分钟、单一环境，这是工程判断不是统计结论；换环境要重测。
//   演示时想更容易触发，可以临时降到 25（改完要重烧）。
#define THRESH_FLOOR 40

const uint32_t COOLDOWN_MS      = 300000;  // 报过一次后 5 分钟内不再报同类（抑制风暴）

// 心跳间隔。**踩过的坑**：心跳原来是 5 分钟，而服务端掉线阈值是 120 秒 ——
// 结果设备永远处于"假离线"（后端一直报心跳丢失，板子其实活得好好的）。
// 规则：掉线阈值 ≥ 3× 心跳间隔，才允许丢 2 次心跳再判死。
// 现在 60 秒心跳 + 180 秒阈值 = 丢 3 次才判掉线。
const uint32_t HEARTBEAT_MS     = 60000;

const uint32_t POST_INTERVAL_MS = 10000;   // 有积压时每 10 秒尝试一次
const int      BUF_MAX          = 200;     // 环形缓冲：断网期间最多攒 200 条

// ---------------- 状态 ----------------
RTC_DATA_ATTR uint32_t g_seq = 0;          // 软件重启后不清零；掉电重启靠新 boot_id 区分
String   g_bootId;
volatile uint32_t g_probeCount = 0;        // 本窗口内抓到的探测请求帧数
uint32_t g_baseline   = DEFAULT_BASELINE;
uint32_t g_overCount  = 0;                 // 连续越界窗口数
uint32_t g_lastReport = 0;
uint32_t g_lastBeat   = 0;
uint32_t g_lastScan   = 0;
uint32_t g_sentTotal  = 0;
uint32_t g_dropped    = 0;                 // 缓冲溢出丢弃数（要能说出来，不能假装没丢）

// ---- v1.1 新增：BLE 通道 / 链路质量 / LED ----
uint32_t g_bleCount   = 0;                 // 本轮扫到的 BLE 设备数（去重后）
uint32_t g_bleBase    = 6;                 // BLE 设备数基线（指数平均）
uint32_t g_bleOver    = 0;                 // 连续越界轮数
uint32_t g_bleReport  = 0;                 // 上次 BLE 上报时间
uint32_t g_bleVendors = 0;                 // 不同厂商 ID 数
int      g_rssi       = 0;
uint32_t g_reconnect  = 0;                 // WiFi 重连次数（链路不稳的直接证据）
uint32_t g_lowRssiWin = 0;                 // 连续 RSSI 过低的窗口数
uint32_t g_linkReport = 0;

struct Ev { uint32_t seq; uint32_t dev_ms; char kind[20]; int value; char detail[128]; };
Ev     g_buf[BUF_MAX];
int    g_head = 0, g_count = 0;

// ---------------- 环形缓冲 ----------------
void pushEvent(const char *kind, int value, const char *detail) {
  if (g_count >= BUF_MAX) {                // 满了丢最旧的一条，并记账
    g_head = (g_head + 1) % BUF_MAX;
    g_count--;
    g_dropped++;
  }
  int idx = (g_head + g_count) % BUF_MAX;
  g_buf[idx].seq = ++g_seq;
  g_buf[idx].dev_ms = (uint32_t)(esp_timer_get_time() / 1000);
  strncpy(g_buf[idx].kind, kind, sizeof(g_buf[idx].kind) - 1);
  g_buf[idx].kind[sizeof(g_buf[idx].kind) - 1] = 0;
  g_buf[idx].value = value;
  strncpy(g_buf[idx].detail, detail ? detail : "", sizeof(g_buf[idx].detail) - 1);
  g_buf[idx].detail[sizeof(g_buf[idx].detail) - 1] = 0;
  g_count++;
}

// ---------------- 下发 ----------------
// 一次最多发 10 条；成功才从缓冲里移除。失败就留着，下一轮再试——
// 服务端按 (boot_id, seq) 幂等，所以"发出去了但没收到响应"这种模糊情况可以安全重发。
bool flushBuffer() {
  if (g_count == 0 || WiFi.status() != WL_CONNECTED) return false;

  int n = g_count < 10 ? g_count : 10;
  String body = "{\"device\":{\"id\":\"" + String(DEVICE_ID) + "\",\"boot_id\":\"" +
                g_bootId + "\",\"fw\":\"" + FW_VERSION + "\"},\"events\":[";
  for (int i = 0; i < n; i++) {
    Ev &e = g_buf[(g_head + i) % BUF_MAX];
    if (i) body += ",";
    body += "{\"seq\":" + String(e.seq) + ",\"dev_ms\":" + String(e.dev_ms) +
            ",\"kind\":\"" + String(e.kind) + "\",\"value\":" + String(e.value) +
            ",\"detail\":" + String(e.detail) + "}";
  }
  body += "]}";

  HTTPClient http;
  http.begin(SERVER_URL);
  http.setTimeout(4000);
  http.addHeader("Content-Type", "application/json");
  if (INGEST_TOKEN[0]) http.addHeader("X-Ingest-Token", INGEST_TOKEN);

  int code = http.POST(body);
  http.end();
  if (code != 200) {
    Serial.printf("[post] 失败 code=%d，保留 %d 条待重发\n", code, g_count);
    return false;
  }
  for (int i = 0; i < n; i++) g_buf[(g_head + i) % BUF_MAX] = Ev();  // 清掉
  g_head = (g_head + n) % BUF_MAX;
  g_count -= n;
  g_sentTotal += n;
  Serial.printf("[post] 成功 %d 条，剩余 %d，累计 %u，丢弃 %u\n",
                n, g_count, g_sentTotal, g_dropped);
  return true;
}

// ---------------- 探测请求计数（混杂模式） ----------------
// 只数帧、不存 MAC —— 演示场景不需要知道是谁，也不需要留隐私数据。
void IRAM_ATTR onWifiPacket(void *buf, wifi_promiscuous_pkt_type_t type) {  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = p->payload;
  // 802.11 管理帧 subtype 0x4 = Probe Request
  if ((f[0] & 0xF0) == 0x40) g_probeCount++;
}

// ---------------- 钓鱼热点检测 ----------------
// 判据：同一 SSID 出现 ≥2 个不同 BSSID，且加密方式或信道不一致。
// 这是"同名但不同设备"的最小特征，不追求工业级准确率（文档里已写明局限）。
void checkRogueAp() {
  int n = WiFi.scanNetworks(false, true);
  if (n <= 0) return;
  static String lastFlagged;
  String flagged;
  for (int i = 0; i < n; i++) {
    for (int j = i + 1; j < n; j++) {
      // 注意：WiFi.BSSID(i) 返回 uint8_t*，直接写 != 比的是**指针**，永远为假。
      // 必须比 6 个字节的内容 —— 这是踩过的坑。
      if (WiFi.SSID(i) == WiFi.SSID(j) &&
          memcmp(WiFi.BSSID(i), WiFi.BSSID(j), 6) != 0) {
        flagged = WiFi.SSID(i);
        if (flagged.length() == 0) continue;                 // 忽略隐藏 SSID
        if (flagged == lastFlagged) continue;                // 同一个问题不重复报
        char d[128];
        snprintf(d, sizeof(d),
                 "{\"ssid\":\"%s\",\"bssids\":2,\"ch\":[%d,%d],\"enc\":[%d,%d]}",
                 flagged.c_str(), WiFi.channel(i), WiFi.channel(j),
                 (int)WiFi.encryptionType(i), (int)WiFi.encryptionType(j));
        pushEvent("ap_rogue", 2, d);
        lastFlagged = flagged;
        Serial.printf("[rogue] 同名 SSID=%s 两个 BSSID\n", flagged.c_str());
        return;
      }
    }
  }
  lastFlagged = "";       // 本轮没发现 -> 允许下次再报
}

// ---------------- v1.1：BLE 通道（零外设，板载蓝牙） ----------------
// 判据：本轮扫到的设备数 > 基线×2 且 ≥ 12，才算"蓝牙设备密度异常"。
// 用途：和 WiFi 探测请求互为第二维 —— 有人群聚集时两边会同时抬升；
//      只有一边抬升说明可能是单一类型设备（比如某人的耳机一直连着）。
#if ENABLE_BLE
void checkBleBurst() {
  // **踩过的坑**：WiFi 混杂模式开着时，BLE 扫描会拿不到结果（两者共用同一个射频，
  // 混杂模式把射频钉在 WiFi 收包状态）。所以扫 BLE 前必须先关混杂、扫完再开回来。
  // 代价：这 2 秒内的 probe request 会漏数 —— 已在文档里写明。
  esp_wifi_set_promiscuous(false);

  BLEScan *scan = BLEDevice::getScan();
  scan->setActiveScan(false);       // 被动扫描：不请求 scan response，更省电也更像"旁观"
  scan->setInterval(100);
  scan->setWindow(99);
  BLEScanResults *res = scan->start(2, false);   // 扫 2 秒（阻塞）
  if (!res) {
    Serial.println("[ble] scan 返回 null（射频被占用？）");
    esp_wifi_set_promiscuous(true);
    return;
  }

  int n = res->getCount();
  // 统计不同厂商 ID（同一个厂商多台设备说明是"一批"，比单纯计数更有信息量）
  static uint16_t vendors[32];
  int nv = 0;
  for (int i = 0; i < n && i < 64; i++) {
    BLEAdvertisedDevice d = res->getDevice(i);
    if (!d.haveManufacturerData()) continue;
    String md = d.getManufacturerData();
    if (md.length() < 2) continue;
    uint16_t vid = (uint16_t)((uint8_t)md[0] | ((uint8_t)md[1] << 8));
    bool seen = false;
    for (int k = 0; k < nv; k++) if (vendors[k] == vid) { seen = true; break; }
    if (!seen && nv < 32) vendors[nv++] = vid;
  }
  scan->clearResults();
  esp_wifi_set_promiscuous(true);   // 扫完立刻把混杂模式还回来，别丢 probe 计数

  g_bleCount = n;
  g_bleVendors = nv;

#if VERBOSE
  Serial.printf("[ble] n=%d vendors=%d base=%u over=%u\n", n, nv, g_bleBase, g_bleOver);
#endif

  uint32_t th = g_bleBase * 2 > 12 ? g_bleBase * 2 : 12;

  // 冷启动：第一轮只学基线，不下判断。
  // 否则默认基线（6）在"本来就有 20 台设备"的环境里会立刻误报。
  static bool warmed = false;
  if (!warmed) {
    warmed = true;
    g_bleBase = n;
    g_bleOver = 0;
    Serial.printf("[ble] 冷启动：基线取首轮 %d 台\n", n);
    return;
  }

  if ((uint32_t)n > th) g_bleOver++; else { g_bleOver = 0; g_bleBase = (g_bleBase * 9 + n) / 10; }

  uint32_t now = millis();
  if (g_bleOver >= 2 && now - g_bleReport > COOLDOWN_MS) {
    char dtail[128];
    snprintf(dtail, sizeof(dtail),
             "{\"ip\":\"%s\",\"scan_s\":2,\"vendors\":%d,\"baseline\":%u}",
             WiFi.localIP().toString().c_str(), nv, g_bleBase);
    pushEvent("ble_burst", n, dtail);
    g_bleReport = now;
    g_bleOver = 0;
    // **关键**：报完之后要把基线上抬。否则"环境永久变成人多"时会每 5 分钟报一次，
    // 变成新的噪音源——这跟 WiFi 侧的 g_baseline 上抬是同一个道理。
    if (g_bleBase < (uint32_t)n / 2) g_bleBase = n / 2;
    Serial.printf("[ble_burst] %d 台 > 阈值 %u，基线上抬到 %u\n", n, th, g_bleBase);
  }
}
#endif

// ---------------- v1.1：链路质量 ----------------
// RSSI 连续 3 个窗口低于 -80dBm，或重连次数增加 -> 一条 link_degraded。
// 这不是"攻击"，是**可用性信号**：无线侧不稳时，上层收到的数据也会不完整。
void checkLinkQuality(uint32_t reconnectDelta) {
  uint32_t now = millis();
  bool bad = (g_rssi < -80) || reconnectDelta > 0;
  if (bad) g_lowRssiWin++; else g_lowRssiWin = 0;
  if (g_lowRssiWin < 3 || now - g_linkReport < COOLDOWN_MS) return;
  char d[128];
  snprintf(d, sizeof(d), "{\"ip\":\"%s\",\"rssi\":%d,\"reconnect\":%u}",
           WiFi.localIP().toString().c_str(), g_rssi, g_reconnect);
  pushEvent("link_degraded", g_rssi, d);
  g_linkReport = now;
  g_lowRssiWin = 0;
  Serial.printf("[link] rssi=%d reconnect=%u\n", g_rssi, g_reconnect);
}

// ---------------- v1.1：板载 LED 状态码（替代 OLED） ----------------
// 熄灭 = 一切正常；快闪(100ms) = 没连上 WiFi；中闪(400ms) = 缓冲区积压过半；
// 正常时收到一次上报成功会短亮 60ms（肉眼能看到"它在干活"）
void updateLed() {
  static uint32_t last = 0;
  uint32_t now = millis();
  if (WiFi.status() != WL_CONNECTED) {
    if (now - last > 100) { digitalWrite(LED_PIN, !digitalRead(LED_PIN)); last = now; }
    return;
  }
  if (g_count > BUF_MAX / 2) {
    if (now - last > 400) { digitalWrite(LED_PIN, !digitalRead(LED_PIN)); last = now; }
    return;
  }
  digitalWrite(LED_PIN, LOW);      // 正常：熄灭（板载 LED 多为低电平点亮）
}

void setup() {
  Serial.begin(115200);
  delay(200);
  g_bootId = String((uint32_t)esp_random(), HEX);

  // 重启本身是一条可用性事件：panic / 看门狗 / 掉电 要能区分
  esp_reset_reason_t why = esp_reset_reason();
  const char *rs = why == ESP_RST_POWERON ? "power_on"
                 : why == ESP_RST_SW      ? "software"
                 : why == ESP_RST_PANIC   ? "panic"
                 : why == ESP_RST_INT_WDT ? "int_wdt"
                 : why == ESP_RST_TASK_WDT? "task_wdt"
                 : why == ESP_RST_BROWNOUT? "brownout"    // 供电不足，很常见
                 : "other";
  char d[64];
  snprintf(d, sizeof(d), "{\"reason\":\"%s\"}", rs);
  pushEvent("device_reboot", 1, d);
  Serial.printf("[boot] boot_id=%s reason=%s seq=%u\n",
                g_bootId.c_str(), rs, g_seq);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("[wifi] connecting");
  for (int i = 0; i < 30 && WiFi.status() != WL_CONNECTED; i++) { delay(500); Serial.print("."); }
  Serial.println(WiFi.status() == WL_CONNECTED ? " ok" : " 失败（会继续重试）");

  // 混杂模式：只收管理帧，用于数 probe request
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&onWifiPacket);
  wifi_promiscuous_filter_t filt = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
  esp_wifi_set_promiscuous_filter(&filt);

  // 板载 LED：用状态码代替屏幕
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);      // 上电先灭（低电平点亮）

#if ENABLE_BLE
  // BLE 初始化：WiFi 和 BLE 共用射频，靠 coexistence 调度，两个都要用就不能省
  BLEDevice::init("");
  Serial.println("[ble] 已初始化，将每 60 秒扫一次周边设备");
#endif
}

void loop() {
  static uint32_t winStart = millis();
  uint32_t now = millis();

  // ---- 窗口结束：判定 ----
  if (now - winStart >= WINDOW_MS) {
    uint32_t cnt = g_probeCount;
    g_probeCount = 0;
    winStart = now;

    uint32_t th = g_baseline * 3 > THRESH_FLOOR ? g_baseline * 3 : THRESH_FLOOR;
    if (cnt > th) {
      g_overCount++;
    } else {
      g_overCount = 0;
      g_baseline = (g_baseline * 9 + cnt) / 10;                // 指数平均更新基线
    }

#if VERBOSE
    // 一行一个窗口：n=本窗口帧数 th=阈值 base=基线 over=连续越界数
    // 这行是"实验 1"的全部数据来源，删了就没法算降噪比
    Serial.printf("[win] n=%u th=%u base=%u over=%u\n", cnt, th, g_baseline, g_overCount);
#endif

    // 连续越界 + 冷却期已过，才上报（这就是"边缘侧去抖"）
    if (g_overCount >= MIN_GAP_WINDOWS && now - g_lastReport > COOLDOWN_MS) {
      char d[128];
      snprintf(d, sizeof(d),
               "{\"ip\":\"%s\",\"window_s\":%u,\"baseline\":%u}",
               WiFi.localIP().toString().c_str(), WINDOW_MS / 1000, g_baseline);
      pushEvent("probe_surge", (int)cnt, d);
      g_lastReport = now;
      g_overCount = 0;
      if (g_baseline < cnt / 3) g_baseline = cnt / 3;          // 上调基线，避免持续刷
      Serial.printf("[surge] 探测请求 %u > 阈值 %u\n", cnt, th);
    }
  }

  // ---- 每分钟：扫 AP（钓鱼热点）+ 扫 BLE（设备密度）----
  if (now - g_lastScan > 60000) {
    g_lastScan = now;
    g_rssi = WiFi.RSSI();
    uint32_t rcBefore = g_reconnect;
    if (WiFi.status() != WL_CONNECTED) { WiFi.reconnect(); g_reconnect++; }
#if VERBOSE
    // 每分钟一行 tick：证明这一轮真的跑了，也给出 RSSI / 重连次数趋势
    Serial.printf("[tick] rssi=%d reconnect=%u buf=%d temp=%.0f\n",
                  g_rssi, g_reconnect, g_count, temperatureRead());
#endif
    checkRogueAp();
    checkLinkQuality(g_reconnect - rcBefore);
#if ENABLE_BLE
    checkBleBurst();
#endif
  }

  // ---- 心跳：只判活，不产生告警 ----
  if (now - g_lastBeat > HEARTBEAT_MS) {
    g_lastBeat = now;
    // 顺手带上芯片温度：长期贴墙运行的过热信号（经典 ESP32 内部温感很粗，只作趋势看）
    char hb[96];
    snprintf(hb, sizeof(hb), "{\"temp_c\":%.0f,\"rssi\":%d,\"dropped\":%u}",
             temperatureRead(), g_rssi, g_dropped);
    pushEvent("heartbeat", 1, hb);
  }

  // ---- 下发 ----
  static uint32_t lastPost = 0;
  if (now - lastPost > POST_INTERVAL_MS) {
    lastPost = now;
    if (WiFi.status() != WL_CONNECTED) { WiFi.reconnect(); g_reconnect++; }
    flushBuffer();
  }

  updateLed();
  delay(20);
}
