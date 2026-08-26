import "@testing-library/jest-dom/vitest";
import React from "react";
import { vi } from "vitest";

globalThis.React = React;

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

Object.defineProperty(window, "ResizeObserver", {
  writable: true,
  value: class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
});

Object.defineProperty(window, "scrollTo", {
  writable: true,
  value: vi.fn(),
});

if (!globalThis.crypto?.randomUUID) {
  Object.defineProperty(globalThis, "crypto", {
    writable: true,
    value: {
      randomUUID: vi.fn(() => "test-random-uuid"),
    },
  });
}

vi.mock("framer-motion", () => {
  const passthrough = (Tag) =>
    React.forwardRef(({ children, ...props }, ref) =>
      React.createElement(Tag, { ...props, ref }, children)
    );
  return {
    AnimatePresence: ({ children }) => <>{children}</>,
    motion: {
      div: passthrough("div"),
      button: passthrough("button"),
      span: passthrough("span"),
      aside: passthrough("aside"),
      section: passthrough("section"),
      h1: passthrough("h1"),
      p: passthrough("p"),
      main: passthrough("main"),
    },
  };
});

vi.mock("recharts", () => {
  const Box = ({ children, ...props }) => <div data-recharts={props.dataKey || props.name || "box"}>{children}</div>;
  return {
    LineChart: Box,
    Line: Box,
    XAxis: Box,
    YAxis: Box,
    Tooltip: Box,
    ResponsiveContainer: Box,
    CartesianGrid: Box,
    Legend: Box,
  };
});
