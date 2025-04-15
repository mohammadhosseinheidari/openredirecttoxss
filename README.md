# openredirecttoxss
This tool allows you to test if an **Open Redirect vulnerability** in a URL can be escalated to a **client-side XSS** using `javascript:` payloads. It uses **Selenium WebDriver** to load the crafted URLs in a real browser and detect if an `alert()` is triggered.
