"""Static dashboard contract and browser checks; no CloudLab access required."""
import functools
import http.server
import json
from pathlib import Path
import threading
import unittest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

ROOT = Path(__file__).resolve().parents[1]
NAMES = ('scheduler', 'kapi', 'memory', 'io', 'virt-ept', 'virt-io',
         'virt-virtio', 'virt-vtd')
SIZES = ((1280, 720), (1366, 768), (1440, 900), (1920, 1080),
         (1024, 768), (390, 844))


class StructureTests(unittest.TestCase):
    def test_three_files_per_experiment(self):
        for name in NAMES:
            self.assertEqual({p.name for p in (ROOT / 'app/views' / name).iterdir()},
                             {f'{name}.{ext}' for ext in ('html', 'css', 'js')})


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@unittest.skipUnless(sync_playwright, 'Install Playwright to run browser checks')
class BrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(
            ('127.0.0.1', 0), functools.partial(QuietHandler, directory=str(ROOT)))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.driver = sync_playwright().start()
        cls.browser = cls.driver.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.driver.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def open_view(self, page, name):
        page.goto(f'{self.base}/app/views/{name}/{name}.html')
        page.wait_for_function("['ready','error','unavailable'].includes(document.documentElement.dataset.captureState)")

    def test_layouts_and_inspector(self):
        for name in NAMES:
            page = self.browser.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            self.open_view(page, name)
            expected = 'ready' if (ROOT / 'captures' / name / 'events.ndjson').exists() else 'unavailable'
            self.assertEqual(page.locator('html').get_attribute('data-capture-state'), expected, name)
            if expected == 'ready':
                scrub = page.locator('input[type="range"]')
                if scrub.count():
                    for fraction in (0.25, 0.5, 1, 0):
                        scrub.first.evaluate('(node,fraction) => {node.value = Math.round(Number(node.max) * fraction); node.dispatchEvent(new Event("input", {bubbles:true}));}', fraction)
                phase_buttons = page.locator('.roadmap button')
                for index in range(min(phase_buttons.count(), 8)):
                    phase_buttons.nth(index).click()
            for width, height in SIZES:
                with self.subTest(name=name, size=(width, height)):
                    page.set_viewport_size({'width': width, 'height': height - 48})
                    page.wait_for_timeout(150)
                    self.assertFalse(page.evaluate('document.documentElement.scrollWidth > innerWidth + 1'))
                    box = page.locator('#capture-refresh').bounding_box()
                    self.assertGreaterEqual(box['y'], 0)
                    self.assertLessEqual(box['y'] + box['height'], height - 48 + 1)
                    toggle = page.locator('#details-toggle')
                    if toggle.is_visible():
                        toggle.click()
                        self.assertEqual(toggle.get_attribute('aria-expanded'), 'true')
                        self.assertTrue(page.locator('.view-details').is_visible())
                        page.keyboard.press('Escape')
                        self.assertEqual(toggle.get_attribute('aria-expanded'), 'false')
                        self.assertTrue(toggle.evaluate('(node) => node === document.activeElement'))
            self.assertEqual(errors, [], name)
            page.close()

    def test_capture_contract(self):
        page = self.browser.new_page()
        page.goto(f'{self.base}/app/')
        result = page.evaluate('''async () => {
            const {parseCapture, relativeNs, values} = await import('/app/common.js');
            const make = (sequence, domain, kind, timestamp) => ({
                experiment:'kapi', sequence, source:{domain, mechanism:'module'},
                clock_domain:domain+':monotonic', timestamp_ns:timestamp, kind,
                context:{}, quality:{status:'complete',reasons:[]},
                data:kind==='capture_finished'?{validated:true}:{}
            });
            const events=[make(1,'host','capture_started','90071992547409930'),
                make(2,'guest','sample','100'), make(3,'host','capture_finished','90071992547409937')];
            const encode = records => records.map(JSON.stringify).join('\\n');
            const capture=parseCapture(encode(events),'kapi');
            const rejects = text => {try {parseCapture(text,'kapi'); return false} catch {return true}};
            return [relativeNs(capture,events[2])===7, relativeNs(capture,events[1])===0,
                values('90071992547409937')==='90071992547409937', rejects(''), rejects('{}'),
                rejects(encode(events.slice(0,2))), rejects(encode([...events].reverse())),
                rejects(encode(events.map(e=>({...e,experiment:'io'}))))];
        }''')
        self.assertTrue(all(result), result)
        page.close()

    def test_laptop_component_bounds(self):
        # A hidden body can mask overflowing children. Check the actual panels.
        panels = {
            'kapi': '.vas-map, .allocator-links, .task-stage',
            'memory': '.spaces, .vas, .residency, .page-tables',
            'virt-ept': '.stage, .state-body, .walk',
            'virt-virtio': '.topology-stage, .queue-region',
        }
        for name, selector in panels.items():
            page = self.browser.new_page()
            self.open_view(page, name)
            for width, height in ((1280, 720), (1366, 768), (1440, 900)):
                with self.subTest(name=name, size=(width, height)):
                    page.set_viewport_size({'width': width, 'height': height - 48})
                    page.wait_for_timeout(150)
                    failures = page.locator(selector).evaluate_all('''nodes => {
                        const bottom = document.querySelector('.view-controls').getBoundingClientRect().top;
                        return nodes.flatMap(node => {
                            const r = node.getBoundingClientRect();
                            return r.x < 0 || r.right > innerWidth + 1 || r.bottom > bottom + 1 || r.height < 40
                                ? [node.className] : [];
                        });
                    }''')
                    self.assertEqual(failures, [])
                    heading = page.locator('h1').first
                    self.assertLessEqual(heading.evaluate('(el) => parseFloat(getComputedStyle(el).fontSize)'), 16)
            page.close()

    def test_scheduler_starts_at_first_snapshot(self):
        page = self.browser.new_page()
        self.open_view(page, 'scheduler')
        self.assertEqual(page.locator('#counter').inner_text().split('/')[0].strip(), '1')
        self.assertEqual(page.locator('#op').inner_text(), 'enqueue_entity')
        self.assertLess(page.locator('.tree-panel .empty:visible').count(), page.locator('.tree-panel .empty').count())
        page.close()

    def test_refresh_failure_and_navigation(self):
        page = self.browser.new_page(viewport={'width': 1280, 'height': 720})
        self.open_view(page, 'kapi')
        page.route('**/captures/kapi/events.ndjson', lambda route: route.fulfill(status=200, body='not json'))
        page.locator('#capture-refresh').click()
        page.wait_for_function("document.documentElement.dataset.captureState === 'error'")
        self.assertIn('Invalid JSON', page.locator('#capture-message').inner_text())
        page.unroute('**/captures/kapi/events.ndjson')
        page.locator('#capture-refresh').click()
        page.wait_for_function("document.documentElement.dataset.captureState !== 'loading'")
        page.goto(f'{self.base}/app/')
        page.locator('.view-tab').nth(1).click()
        page.wait_for_function("['ready','unavailable'].includes(document.querySelector('#viewer-frame').contentDocument?.documentElement.dataset.captureState)")
        self.assertIn('kapi', page.locator('#viewer-frame').get_attribute('src'))
        page.close()


if __name__ == '__main__':
    unittest.main()
