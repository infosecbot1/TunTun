import {render, screen} from "@testing-library/react";
import {describe, expect, it} from "vitest";
import {App} from "./app";

describe("App", () => {
  it("renders the offline setup shell", () => {
    render(<App />);
    expect(screen.getByRole("heading", {name: "Tuntun setup in progress"})).toBeVisible();
  });
});
