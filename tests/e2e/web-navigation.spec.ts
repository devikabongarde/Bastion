import { expect, test, type Page } from "@playwright/test";

async function unauthenticated(page: Page) {
  await page.route("**/health/live", (route) => route.fulfill({ json: { status: "live" } }));
  await page.route("**/api/v1/me", (route) => route.fulfill({
    status: 401,
    contentType: "application/problem+json",
    body: JSON.stringify({ status: 401, code: "AUTHENTICATION_REQUIRED", title: "Authentication required", detail: "Sign in to continue.", request_id: "synthetic-test" }),
  }));
}

test("unauthenticated visitors see the landing page, never the console", async ({ page }) => {
  await unauthenticated(page);
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Open the console" }).first()).toBeVisible();
  await expect(page.locator("#main-content")).toHaveCount(0);
  await page.goto("/findings");
  await expect(page.getByRole("button", { name: "Open the console" }).first()).toBeVisible();
  await expect(page.locator("#main-content")).toHaveCount(0);
});

test("opening the console from the landing page leads to sign-in", async ({ page }) => {
  await unauthenticated(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Open the console" }).first().click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Skip to sign in" })).toBeAttached();
});

test("the sign-in screen does not overflow a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await unauthenticated(page);
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  const d = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  expect(d.content).toBeLessThanOrEqual(d.viewport);
});
