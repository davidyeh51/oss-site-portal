# ACMEPOINT 進金生能源｜維運資產與合約決策平台 (OSS Executive Portal)

線上網址：<https://davidyeh51.github.io/oss-site-portal/>

本專案為 **進金生能源服務股份有限公司（ACMEPOINT Energy Services Co., Ltd.，進能服 · 6692）** 內部專用之維運案場、履約合約、客戶資產與颱風風險戰情平台，採用 **McKinsey 顧問級結構視覺語言 ✕ ACMEPOINT 官方品牌識別**，並串接 **Supabase BaaS + Edge Function + RLS** 建構雙層存取防護。

---

## 核心安全防護架構

1. **第一層：系統存取金鑰門禁（Access Key Gate）**
   - 訪客開啟網頁時須先輸入有效的「存取金鑰（密碼 Key）」，未通過前不會顯示內部功能或業務資料。
   - 所有金鑰皆以隨機 Salt + SHA-256 雜湊儲存於 `public.oss_access_keys`（前端無法直接讀取），驗證一律於後端 Edge Function `oss-account-admin` 採常數時間比對，通過後簽發 24 小時 HMAC-SHA256 憑證並即時檢查金鑰啟用狀態。
   - 系統擁有者（Owner）可於「後台與權限管理 → 存取密碼 Key 門禁」隨時新增、設定到期日、停用或一鍵輪替全域簽章。

2. **第二層：授權帳號與精細角色權限（RBAC + RLS）**
   - 所有案場（`oss_sites`）、合約（`oss_contracts`）、客戶（`oss_customers`）、附件（`oss_files`）皆啟用 Postgres RLS，透過 `oss_is_admin()` 驗證 JWT 與 `oss_admins.enabled = true`。
   - 支援四級角色權限：
     | 角色 | 說明 | 商務金額 | 匯出／雲端下載 | 成員管理 | 金鑰與系統設定 |
     |---|---|---|---|---|---|
     | **Owner（擁有者）** | 系統最高治理權限 | 可檢視 | 允許 | 全部成員 | 完全控制 |
     | **Admin（管理員）** | 部門維運管理員 | 可控管 | 可控管 | 一般／唯讀 | 檢視稽核日誌 |
     | **Member（一般成員）** | 維運團隊同仁 | 可個別設定 | 可個別設定 | 無 | 無 |
     | **Viewer（唯讀訪客）** | 稽核或跨部門檢視 | 自動遮罩 | 強制禁止 | 無 | 無 |

3. **零公開洩漏原則（Zero Public Leakage）**
   - 原先寫死於公開 HTML 的 Google Drive 資料庫網址已全面移出原始碼，改存於受後端保護之 `public.oss_portal_config`，僅在通過雙重驗證且具備 `can_export = true` 時動態回傳。
   - 加入 `robots.txt`（`Disallow: /`）與 `<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">` 防止搜尋引擎收錄。
   - 前端僅暴露公開的 `sb_publishable_*` Client Key，零私鑰或 `service_role` 外洩風險。

---

## 專案目錄結構

```text
oss-site-portal/
├── index.html                                  # McKinsey × ACMEPOINT 前端決策平台與後台控制台
├── robots.txt                                  # 阻擋搜尋引擎索引
├── .nojekyll                                   # GitHub Pages 靜態託管設定
├── assets/
│   ├── acmepoint-logo.png                      # 進金生能源官方彩色 Logo
│   ├── acmepoint-logo-white.png                # 進金生能源官方反白 Logo
│   └── favicon.png                             # 官方網站圖示
└── supabase/
    ├── schema.sql                              # 資料庫安全升級與 RLS 參考腳本
    └── functions/oss-account-admin/index.ts    # 後端門禁驗證、RBAC 與稽核 Edge Function
```
