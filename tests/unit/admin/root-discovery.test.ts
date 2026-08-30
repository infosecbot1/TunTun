import {describe, expect, it} from "vitest";
import {App} from "../../../apps/admin/src/app";

describe("root unit-test discovery", () => {
  it("loads an admin module from the root test tree", () => {
    expect(typeof App).toBe("function");
  });
});
