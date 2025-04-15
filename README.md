# 🔍 Open Redirect to XSS Checker (Selenium-Based)

This tool allows you to test if an **Open Redirect vulnerability** in a URL can be escalated to a **client-side XSS** using `javascript:` payloads. It uses **Selenium WebDriver** to load the crafted URLs in a real browser and detect if an `alert()` is triggered.

---

## 💡 How It Works

1. Takes a URL with a placeholder (`FUZZ`) where the payload will be injected.
2. Replaces the placeholder with encoded `javascript:` payloads.
3. Opens each test URL in a browser via Selenium.
4. Waits to see if an `alert()` pops up.
5. Logs success or failure for each payload.

---

## ✅ Example

```bash
python3 xss_checker.py "https://example.com/redirect?next=FUZZ" --browser chrome --headless
```

---

## ⚙️ Arguments

| Argument         | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `url_template`   | URL containing a placeholder for payload injection, like `FUZZ`.            |
| `--placeholder`  | (Optional) Custom placeholder (default: `FUZZ`).                            |
| `--driver-path`  | (Optional) Path to your WebDriver (e.g. `chromedriver` or `geckodriver`).   |
| `--browser`      | (Optional) Choose browser: `chrome` or `firefox` (default: `chrome`).       |
| `--headless`     | (Optional) Run browser in headless mode (no GUI).                           |

---

## 🧱 Dependencies

- Python 3.7+
- [Selenium](https://pypi.org/project/selenium/)
- Google Chrome or Firefox browser
- Corresponding WebDriver (e.g., ChromeDriver or GeckoDriver)

---

## 📆 Install Python Dependencies

```bash
pip install selenium
```

---

## 🛠️ Setup Instructions (Ubuntu)

### 🔹 Install Google Chrome

```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```

### 🔹 Check Chrome Version

```bash
google-chrome --version
```

### 🔹 Download Matching ChromeDriver

1. Visit [https://chromedriver.chromium.org/downloads](https://chromedriver.chromium.org/downloads)
2. Match it to your Chrome version
3. Then:

```bash
wget https://chromedriver.storage.googleapis.com/<VERSION>/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
chmod +x chromedriver
sudo mv chromedriver /usr/local/bin/
```

Replace `<VERSION>` with the correct driver version number.

### 🔹 Confirm Installation

```bash
chromedriver --version
```

---

## 🥪 Sample Output

```text
[*] Initialized Selenium checker for URL template: https://test.com/redirect?url=FUZZ
[*] Placeholder: FUZZ
[*] Browser Type: chrome
[*] WebDriver Path: Using PATH
[*] Headless Mode: True

[*] Starting All Payload Tests with Selenium...

[*] Testing Payload via Selenium: javascript:alert(document.domain)
    Generated URL: https://test.com/redirect?url=javascript%3Aalert(document.domain)
    Navigating...
    Waiting up to 5 seconds for alert...
    [+] Alert detected! Text: 'test.com'
    Result: SUCCESS: Alert detected! Text: 'test.com'

[+] Confirmed Open Redirect to XSS Execution!
    The following payloads successfully triggered an alert in the browser:
    - Payload: javascript:alert(document.domain)
      URL: https://test.com/redirect?url=javascript%3Aalert(document.domain)
```

---

## ⚠️ Legal & Ethical Use

This tool is intended for **authorized penetration testing and educational purposes only**. Do **not** run it against systems you don’t have permission to test. Unauthorized testing may be illegal and unethical.

---

## 📃 License

MIT License
