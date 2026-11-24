# ACMEPOINT 進金生能源｜維運資產與合約決策平台 (OSS Executive Portal)

線上網址：<https://davidyeh51.github.io/oss-site-portal/>

本專案為 **進金生能源服務股份有限公司（ACMEPOINT Energy Services Co., Ltd.，進能服 · 6692）** 內部專用之維運案場、履約合約、客戶資產與颱風風險戰情平台，採用 **McKinsey 顧問級結構視覺語言 ✕ ACMEPOINT 官方品牌識別**，並串接 **Supabase BaaS + Edge Function + RLS** 建構分級存取金鑰保護與完整後台管理系統。

---

## 核心功能與安全架構

1. **分級系統存取金鑰（Role-Scoped Access Key Gate）**
   - 支援「單一步驟存取金鑰（Access Key）」快速解鎖進入平台，同時依金鑰權限等級（`owner` / `admin` / `member` / `viewer`）動態控管功能：
     - `owner`（最高擁有者）：全系統檢視、CSV 匯出、商務條款檢視、輪替金鑰與後台最高權限。
     - `admin`（管理員）：全系統檢視、CSV 匯出、商務條款檢視與後台管理。
     - `member`（內部維運同仁）：完整案場／合約／客戶／地圖檢視與匯出，不開放後台管理。
     - `viewer`（唯讀訪客／外部稽核）：僅可檢視基本規格與地圖，自動遮罩商務金額／保發條款並停用 CSV 匯出。
   - 金鑰以隨機 Salt + SHA-256 雜湊儲存於 `public.oss_access_keys`（前端無法直接讀取），驗證通過後由後端 `oss-account-admin` 動態簽發資料庫讀取憑證，確保未通過驗證前 RLS 阻斷一切匿名存取。

2. **管理員後台控制台（Exhibit 06 · Admin Console）**
   - 僅 `owner` / `admin` 金鑰解鎖後顯示「後台管理」分頁，可於網頁上直接：
     - 發行、停用、刪除各權限等級之存取金鑰（支援自訂到期強制鎖定與 60 天週期提醒）。
     - 線上維護系統設定（公司雲端資料庫 Google Drive 連結、機密公告橫幅）。
     - 管理公司授權人員名錄（`oss_admins`）。
     - 即時查閱最近 80 筆安全稽核日誌（成功／失敗解鎖、報表匯出、金鑰發行／輪替、設定異動）。

3. **McKinsey × ACMEPOINT 高階執行摘要總覽（Exhibit 00 · Executive Overview）**
   - 整合進金生能源官方品牌（[acmepointes.com/zh-tw](https://www.acmepointes.com/zh-tw)）之五大綠能解決方案（太陽光電、儲能與微電網、電廠維運與服務、地熱發電、碳封存）、TÜV 太陽光電維運 AAA 級認證與四大區域據點，並提供區域容量結構圖與合約到期風險優先矩陣。

4. **多平台風雨戰情地圖（Google 地圖 ＋ 開放型地圖）**
   - 支援 Google 地圖、Google 衛星混合圖、內政部國土測繪電子地圖 (NLSC)、CartoDB Voyager、OpenStreetMap 五種底圖切換，結合氣象署即時風雨與颱風路徑風險判定。
