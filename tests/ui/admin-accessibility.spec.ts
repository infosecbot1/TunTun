import AxeBuilder from "@axe-core/playwright";
import {expect, test} from "@playwright/test";

test("has no serious or critical baseline accessibility violations", async ({page}) => {
  await page.goto("/");
  const result = await new AxeBuilder({page}).analyze();
  expect(result.violations.filter(({impact}) => impact === "serious" || impact === "critical")).toHaveLength(0);
});
