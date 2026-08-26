import React from "react";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const rootRender = vi.hoisted(() => vi.fn());
const createRoot = vi.hoisted(() => vi.fn(() => ({ render: rootRender })));

vi.mock("react-dom/client", () => ({ createRoot }));
vi.mock("@/routes/AppRouter", () => ({
  default: () => <div>router mounted</div>,
}));
vi.mock("@/context/AuthContext", () => ({
  AuthProvider: ({ children }) => <div data-testid="auth-provider">{children}</div>,
}));

describe("application entry coverage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.body.innerHTML = '<div id="root"></div>';
  });

  it("renders App with auth and routing providers", async () => {
    const { default: App } = await import("./App.jsx");

    render(<App />);

    expect(screen.getByTestId("auth-provider")).toBeInTheDocument();
    expect(screen.getByText("router mounted")).toBeInTheDocument();
  });

  it("boots the Vite entrypoint into the root element", async () => {
    await import("./main.jsx");

    expect(createRoot).toHaveBeenCalledWith(document.getElementById("root"));
    expect(rootRender).toHaveBeenCalledTimes(1);
  });
});
