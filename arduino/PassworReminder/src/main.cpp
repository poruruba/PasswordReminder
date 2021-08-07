#include <M5StickC.h>
#include <Preferences.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include "BLE2902.h"
#include "BLEHIDDevice.h"
#include "HIDTypes.h"
#include "HIDKeyboardTypes.h"
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <efontEnableJa.h>
#include <efontFontData.h>
#define LGFX_AUTODETECT
#include <LovyanGFX.hpp>

const char *wifi_ssid = "【WiFiアクセスポイントのSSID】"; // WiFiアクセスポイントのSSID
const char *wifi_password = "【WiFiアクセスポイントのパスワード】"; // WiFiアクセスポイントのパスワード
const char *apikey = "【パスワードサーバのAPIKey】";
const char *endpoint = "【サーバのURL】/pwd-allpasswd";

#define LCD_BRIGHTNESS  64  // LCDのバックライトの輝度(0～255)
#define WIFI_TIMEOUT  10000 // WiFiアクセスポイント接続時タイムアウト時間
const char *pref_name = "pwd_list"; // 不揮発メモリのネームスペース(<=15文字)
const char *pref_key = "list"; // 不揮発メモリのキー名
const char *device_name = "Password-Reminder"; // BLEデバイス名

Preferences pref; // 不揮発メモリアクセス用
static LGFX lcd; // for LovyanGFX
short current_index = -1; // 現在選択中のタイトルの番号。初期は未選択状態

// HTTP POST/GETのレスポンス用ArduinoJson変数
const int capacity_response = JSON_OBJECT_SIZE(256);
StaticJsonDocument<capacity_response> json_response;
// ArduinoJsonのパース用バッファ
char json_buffer[5120];

// 関数宣言
void print_screen(void);
const char *get_title(unsigned short index);
const char *get_userid(unsigned short index);
const char *get_password(unsigned short index);
short get_num(void);
long wifi_connect(const char *ssid, const char *password, unsigned long timeout);
long do_post_with_apikey(const char *p_endpoint, JsonDocument *p_input, JsonDocument *p_output, const char *apikey);
long reload_password(JsonDocument *p_output);
long save_password(JsonDocument *p_output);

/*
 * BLEデバイス処理
 */
BLEHIDDevice *hid;
BLECharacteristic *input;
BLECharacteristic *output;

bool connected = false;

class MyCallbacks : public BLEServerCallbacks
{
  void onConnect(BLEServer *pServer){
    connected = true;
    BLE2902 *desc = (BLE2902 *)input->getDescriptorByUUID(BLEUUID((uint16_t)0x2902));
    desc->setNotifications(true);
  }

  void onDisconnect(BLEServer *pServer){
    connected = false;
    BLE2902 *desc = (BLE2902 *)input->getDescriptorByUUID(BLEUUID((uint16_t)0x2902));
    desc->setNotifications(false);
  }
};

// ペアリング処理用
class MySecurity : public BLESecurityCallbacks
{
  bool onConfirmPIN(uint32_t pin){
    return false;
  }

  uint32_t onPassKeyRequest(){
    Serial.println("ONPassKeyRequest");
    return 123456;
  }

  void onPassKeyNotify(uint32_t pass_key){
    // ペアリング時のPINの表示
    Serial.println("onPassKeyNotify number");
    Serial.println(pass_key);

    lcd.fillScreen(BLACK);
    lcd.setCursor(0, 0);
    lcd.println("PIN");
    lcd.println(pass_key);
  }

  bool onSecurityRequest(){
    Serial.println("onSecurityRequest");
    return true;
  }

  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl){
    Serial.println("onAuthenticationComplete");
    if (cmpl.success){
      // ペアリング完了
      Serial.println("auth success");
      print_screen();
    }else{
      // ペアリング失敗
      Serial.println("auth failed");
    }
  }
};

// BLEデバイスの起動
void taskServer(void *)
{
  BLEDevice::init(device_name);

  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT_MITM);
  BLEDevice::setSecurityCallbacks(new MySecurity());

  BLEServer *pServer = BLEDevice::createServer();
  pServer->setCallbacks(new MyCallbacks());

  hid = new BLEHIDDevice(pServer);
  input = hid->inputReport(1);   // <-- input REPORTID from report map
  output = hid->outputReport(1); // <-- output REPORTID from report map

  std::string name = "Poruruba";
  hid->manufacturer()->setValue(name);

  hid->pnp(0x02, 0xe502, 0xa111, 0x0210);
  hid->hidInfo(0x00, 0x02);

  BLESecurity *pSecurity = new BLESecurity();
  //  pSecurity->setKeySize();

  //  pSecurity->setAuthenticationMode(ESP_LE_AUTH_NO_BOND); // NO Bond
  // AndroidではうまくPIN入力が機能しない場合有り
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_BOND);
  pSecurity->setCapability(ESP_IO_CAP_OUT);
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

  const uint8_t report[] = {
      USAGE_PAGE(1), 0x01, // Generic Desktop Ctrls
      USAGE(1), 0x06,      // Keyboard
      COLLECTION(1), 0x01, // Application
      REPORT_ID(1), 0x01,  //   Report ID (1)
      USAGE_PAGE(1), 0x07, //   Kbrd/Keypad
      USAGE_MINIMUM(1), 0xE0,
      USAGE_MAXIMUM(1), 0xE7,
      LOGICAL_MINIMUM(1), 0x00,
      LOGICAL_MAXIMUM(1), 0x01,
      REPORT_SIZE(1), 0x01, //   1 byte (Modifier)
      REPORT_COUNT(1), 0x08,
      HIDINPUT(1), 0x02,     //   Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position
      REPORT_COUNT(1), 0x01, //   1 byte (Reserved)
      REPORT_SIZE(1), 0x08,
      HIDINPUT(1), 0x01,     //   Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position
      REPORT_COUNT(1), 0x06, //   6 bytes (Keys)
      REPORT_SIZE(1), 0x08,
      LOGICAL_MINIMUM(1), 0x00,
      LOGICAL_MAXIMUM(1), 0x65, //   101 keys
      USAGE_MINIMUM(1), 0x00,
      USAGE_MAXIMUM(1), 0x65,
      HIDINPUT(1), 0x00,     //   Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position
      REPORT_COUNT(1), 0x05, //   5 bits (Num lock, Caps lock, Scroll lock, Compose, Kana)
      REPORT_SIZE(1), 0x01,
      USAGE_PAGE(1), 0x08,    //   LEDs
      USAGE_MINIMUM(1), 0x01, //   Num Lock
      USAGE_MAXIMUM(1), 0x05, //   Kana
      HIDOUTPUT(1), 0x02,     //   Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile
      REPORT_COUNT(1), 0x01,  //   3 bits (Padding)
      REPORT_SIZE(1), 0x03,
      HIDOUTPUT(1), 0x01, //   Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile
      END_COLLECTION(0)};

  hid->reportMap((uint8_t *)report, sizeof(report));
  hid->startServices();

  BLEAdvertising *pAdvertising = pServer->getAdvertising();
  pAdvertising->setAppearance(HID_KEYBOARD);
  pAdvertising->addServiceUUID(hid->hidService()->getUUID());
  pAdvertising->start();
  hid->setBatteryLevel(7);

  Serial.println("Advertising started!");
  delay(portMAX_DELAY);
};

/*
 * Arduinoメイン処理
 */
void setup()
{
  M5.begin();
  M5.Axp.begin();
//  Serial.begin(115200);

  lcd.init(); // M5StickCのLCDの初期化
  lcd.setBrightness(LCD_BRIGHTNESS);
  lcd.setRotation(3);
  lcd.fillScreen(BLACK);
  lcd.setFont(&fonts::efont);
  lcd.setCursor(0, 0);

  lcd.printf("[%s]", device_name);
  Serial.println("start Serial");
  Serial.println("Starting Password-Reminder!");
  lcd.println("start BLE");

  // BLEデバイスの起動処理の開始
  xTaskCreate(taskServer, "server", 20000, NULL, 5, NULL);

  long ret = reload_password(&json_response);
  if( ret == 0 )
    Serial.println("reload_password OK");
  else
    Serial.println("reload_password Error");

  // デフォルト(インデックス=0)のタイトルの存在確認
  if (get_title(0) != NULL)
    current_index = 0;
  else
    current_index = -1;

  // LCDの表示
  print_screen();
}

void loop()
{
  M5.update();

  // ButtonBが押されたとき
  if (M5.BtnB.wasReleased()){
    if (current_index >= 0){
      // いずれかのタイトルが選択されている状態の場合
      current_index++; // 次のタイトルへ
      if( current_index >= get_num() )
        current_index = 0;
    }

    // LCD表示の更新
    print_screen();
  }

  // ButtonAが押されたとき
  if (M5.BtnA.wasReleased()){
    if (connected){
      // BLEキーボードとしてPCに接続されている状態の場合
      if (current_index >= 0){
        // いずれかのタイトルが選択されている状態の場合
        const char *ptr = get_password(current_index);
        if( ptr != NULL ){
          while (*ptr){
            KEYMAP map = keymap[(uint8_t)*ptr];
            uint8_t msg[] = {map.modifier, 0x0, map.usage, 0x0, 0x0, 0x0, 0x0, 0x0};
            input->setValue(msg, sizeof(msg));
            input->notify();
            ptr++;

            uint8_t msg1[] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
            input->setValue(msg1, sizeof(msg1));
            input->notify();

            delay(20);
          }
        }
      }
    }
  }

  if( M5.Axp.GetBtnPress() != 0 ){
    lcd.fillScreen(BLACK);
    lcd.setCursor(0, 0);
    lcd.println("更新中");
    delay(5000);

    bool completed = false;
    long ret;
    ret = wifi_connect(wifi_ssid, wifi_password, WIFI_TIMEOUT);
    if( ret == 0 ){
      ret = do_post_with_apikey(endpoint, NULL, &json_response, apikey);
      if( ret >= 0 ){
        Serial.println("do_post OK");
        ret = save_password(&json_response);
        if( ret == 0 ){
          Serial.println("save_password OK");
          completed = true;
          if (get_title(0) != NULL)
            current_index = 0;
          else
            current_index = -1;
        }
      }
      WiFi.disconnect(true);
    }
    if( completed )
      lcd.println("更新成功");
    else
      lcd.println("更新失敗");
    delay(1000);
    
    // LCD表示の更新
    print_screen();
  }

  delay(1);
}

long wifi_connect(const char *ssid, const char *password, unsigned long timeout)
{
  #define CHECK_INTERVAL  1000

  Serial.println("");
  Serial.print("WiFi Connenting");

  WiFi.disconnect(true);
  WiFi.begin(ssid, password);
  unsigned long elapsed;
  for (elapsed = 0; WiFi.status() != WL_CONNECTED && elapsed < timeout; elapsed += CHECK_INTERVAL){
    Serial.print(".");
    delay(CHECK_INTERVAL);
  }
  if (elapsed >= timeout)
    return -1;

  Serial.println("");
  Serial.print("Connected : ");
  Serial.println(WiFi.localIP());

  return 0;
}

long reload_password(JsonDocument *p_output){
  pref.begin(pref_name, true);
  size_t len = pref.getString(pref_key, json_buffer, sizeof(json_buffer));
  pref.end();
  if (len <= 0)
    return -1;

  DeserializationError err = deserializeJson(*p_output, json_buffer, len);
  if (err){
    Serial.println("Error: deserializeJson");
    return -1;
  }

  return 0;
}

long save_password(JsonDocument *p_output){
  size_t len = serializeJson(*p_output, json_buffer, sizeof(json_buffer));
  if (len < 0 || len >= sizeof(json_buffer)){
    Serial.println("Error: serializeJson");
    return -1;
  }

  pref.begin(pref_name, false);
  len = pref.putString(pref_key, json_buffer);
  pref.end();

  if (len <= 0)
    return -1;
  return 0;
}

// タイトルの取得
const char *get_title(unsigned short index){
  JsonArray list = json_response["result"];
  if( index >= list.size() )
    return NULL;

  return list[index]["name"];
}

// ユーザIDの取得
const char *get_userid(unsigned short index){
  JsonArray list = json_response["result"];
  if (index >= list.size())
    return NULL;

  return list[index]["userid"];
}

// パスワードの取得
const char *get_password(unsigned short index){
  JsonArray list = json_response["result"];
  if (index >= list.size())
    return NULL;

  return list[index]["password"];
}

short get_num(void){
  JsonArray list = json_response["result"];
  return (short)list.size();
}

// M5StickCのLCD表示
//  現在選択中のタイトルとユーザIDの表示
void print_screen(void)
{
  lcd.fillScreen(BLACK);
  lcd.setCursor(0, 0);

  if (current_index < 0){
    lcd.printf("not found");
  }else{
    lcd.printf("(%d) %s\n", current_index, get_title(current_index));
    lcd.printf("%s", get_userid(current_index));
  }
}

long do_post_with_apikey(const char *p_endpoint, JsonDocument *p_input, JsonDocument *p_output, const char *apikey)
{
  HTTPClient http;
  http.begin(p_endpoint);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-KEY", apikey);

  size_t len;
  if( p_input != NULL ){
   len = serializeJson(*p_input, json_buffer, sizeof(json_buffer));
    if (len < 0 || len >= sizeof(json_buffer))
    {
      Serial.println("Error: serializeJson");
      return -1;
    }
  }else{
    strcpy(json_buffer, "{}");
    len = strlen(json_buffer);
  }

  Serial.println("http.POST");
  int status_code = http.POST((uint8_t *)json_buffer, len);
  Serial.printf("status_code=%d\r\n", status_code);
  if (status_code != 200)
  {
    http.end();
    return status_code;
  }

  Stream *resp = http.getStreamPtr();
  DeserializationError err = deserializeJson(*p_output, *resp);
  http.end();

  if (err)
  {
    Serial.println("Error: deserializeJson");
    return -1;
  }

  return 0;
}
