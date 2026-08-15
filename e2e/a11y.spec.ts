import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the crypto unit vectors;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes with every collapsible / hidden region revealed.
 *
 * This lab has no <details> and no [hidden]/display:none exhibit panels — the
 * output <pre> blocks are always in the DOM and populated via textContent.
 * We still defensively expand any <details> and clear inline display:none /
 * [hidden] before scanning, and neutralize animations/transitions so nothing
 * is scanned mid-flight.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.waitForTimeout(250);
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled or inline-hidden panels defensively.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function checkGradientContrast(page: Page): Promise<void> {
  const contrast = await page.evaluate(() => {
    function getLum(r: number, g: number, b: number) {
      const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    function parseRGB(str: string) {
      const m = str.match(/\d+/g);
      return m ? [parseInt(m[0], 10), parseInt(m[1], 10), parseInt(m[2], 10)] : [0,0,0];
    }
    const el = document.querySelector('.cl-hero-desc');
    if (!el) return 0;
    const color = getComputedStyle(el).color;
    let bgStr = getComputedStyle(document.body).backgroundColor;
    if (bgStr === 'rgba(0, 0, 0, 0)' || bgStr === 'transparent') {
      bgStr = getComputedStyle(document.documentElement).backgroundColor;
    }
    const textLum = getLum(...(parseRGB(color) as [number, number, number]));
    const bgLum = getLum(...(parseRGB(bgStr) as [number, number, number]));
    return (Math.max(textLum, bgLum) + 0.05) / (Math.min(textLum, bgLum) + 0.05);
  });
  expect(contrast).toBeGreaterThanOrEqual(4.5);
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await page.locator('.cl-hero-title').waitFor();
  await checkGradientContrast(page);
  await revealAll(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runSuite(page);
});

