import {expect, test} from "@playwright/test";

test("serves the offline setup shell", async ({page}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", {name: "Tuntun setup in progress"})).toBeVisible();
});
