# KeyVault USB —— ESP32-S3 纯 USB 密钥管理设备
# 主组件源文件与依赖声明（注意：不使用 GLOB，避免把 index.html 等卷入编译）
# 固件不依赖 esp_wifi / bt，USB 设备栈通过 idf_component.yml 引入 espressif/esp_tinyusb

idf_component_register(
    SRCS "main.c" "keyvault.c" "usb_net.c" "usb_desc.c" "rndis.c" "usb_hid.c" "web_content.c" "json_util.c" "wifi_net.c" "e2ee.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES
        driver
        esp_event
        esp_http_server
        esp_hw_support
        esp_netif
        esp_timer
        esp_wifi
        mbedtls
        nvs_flash
        espressif__esp_tinyusb
)
