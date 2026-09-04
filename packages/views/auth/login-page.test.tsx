import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement, ReactNode } from "react";
import { I18nProvider } from "@multica/core/i18n/react";
import enCommon from "../locales/en/common.json";
import enAuth from "../locales/en/auth.json";
import enSettings from "../locales/en/settings.json";

const mockLoginWithPassword = vi.hoisted(() => vi.fn());
const mockPasswordLogin = vi.hoisted(() => vi.fn());
const mockListWorkspaces = vi.hoisted(() => vi.fn());
const mockSetQueryData = vi.hoisted(() => vi.fn());
const mockAuthState = vi.hoisted(() => ({ expired: false }));

vi.mock("@tanstack/react-query", async () => {
  const actual = await vi.importActual<typeof import("@tanstack/react-query")>("@tanstack/react-query");
  return { ...actual, useQueryClient: () => ({ setQueryData: mockSetQueryData }) };
});
vi.mock("@multica/core/auth", () => ({
  useAuthStore: Object.assign(
    (selector: (state: typeof mockAuthState) => unknown) => selector(mockAuthState),
    { getState: () => ({ loginWithPassword: mockLoginWithPassword }) },
  ),
}));
vi.mock("@multica/core/api", () => ({
  api: {
    getMe: vi.fn().mockRejectedValue(new Error("unauthorized")), setToken: vi.fn(), issueCliToken: vi.fn(),
    listWorkspaces: mockListWorkspaces, passwordLogin: mockPasswordLogin,
  },
}));

import { LoginPage, validateCliCallback } from "./login-page";

const resources = { en: { common: enCommon, auth: enAuth, settings: enSettings } };
function renderPage(ui: ReactElement) {
  function Wrapper({ children }: { children: ReactNode }) {
    return <I18nProvider locale="en" resources={resources}>{children}</I18nProvider>;
  }
  return render(ui, { wrapper: Wrapper });
}

describe("LoginPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockAuthState.expired = false;
  });

  it("renders LDAP account and password fields", () => {
    renderPage(<LoginPage onSuccess={vi.fn()} />);
    expect(screen.getByText(/sign in with your ldap account/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/account/i)).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText(/password/i)).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByRole("button", { name: /^sign in$/i })).toBeDisabled();
  });

  it("shows when the previous session expired", () => {
    mockAuthState.expired = true;
    renderPage(<LoginPage onSuccess={vi.fn()} />);
    expect(screen.getByText(/your session expired/i)).toBeInTheDocument();
  });

  it("logs in and seeds the workspace cache before completing", async () => {
    const onSuccess = vi.fn();
    mockLoginWithPassword.mockResolvedValue({ id: "user-1" });
    mockListWorkspaces.mockResolvedValue([{ id: "ws-1" }]);
    renderPage(<LoginPage onSuccess={onSuccess} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/account/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "secret");
    await user.click(screen.getByRole("button", { name: /^sign in$/i }));
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce());
    expect(mockLoginWithPassword).toHaveBeenCalledWith("alice", "secret");
    expect(mockSetQueryData).toHaveBeenCalledWith(expect.arrayContaining(["workspaces", "list"]), [{ id: "ws-1" }]);
  });

  it("shows authentication errors without completing", async () => {
    mockLoginWithPassword.mockRejectedValue(new Error("Invalid account or password"));
    const onSuccess = vi.fn();
    renderPage(<LoginPage onSuccess={onSuccess} />);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/account/i), "alice");
    await user.type(screen.getByLabelText(/password/i), "bad");
    await user.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(await screen.findByText("Invalid account or password")).toBeInTheDocument();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("returns the LDAP login token and state to the CLI callback", async () => {
    mockPasswordLogin.mockResolvedValue({
      token: "cli-jwt-token",
      user: { id: "user-1", email: "alice@example.com" },
    });
    const hrefSetter = vi.fn();
    const originalLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: {
        ...originalLocation,
        set href(value: string) {
          hrefSetter(value);
        },
      },
    });

    try {
      renderPage(
        <LoginPage
          onSuccess={vi.fn()}
          cliCallback={{
            url: "http://127.0.0.1:43689/callback",
            state: "opaque-cli-state",
          }}
        />,
      );
      const user = userEvent.setup();
      await user.type(screen.getByLabelText(/account/i), "alice");
      await user.type(screen.getByLabelText(/password/i), "secret");
      await user.click(screen.getByRole("button", { name: /^sign in$/i }));

      await waitFor(() => {
        expect(hrefSetter).toHaveBeenCalledWith(
          "http://127.0.0.1:43689/callback?token=cli-jwt-token&state=opaque-cli-state",
        );
      });
      expect(mockPasswordLogin).toHaveBeenCalledWith("alice", "secret");
      expect(mockLoginWithPassword).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: originalLocation,
      });
    }
  });
});

describe("validateCliCallback", () => {
  it("accepts local HTTP callbacks only", () => {
    expect(validateCliCallback("http://127.0.0.1:9000/callback")).toBe(true);
    expect(validateCliCallback("http://192.168.1.5/callback")).toBe(true);
    expect(validateCliCallback("http://example.com/callback")).toBe(false);
    expect(validateCliCallback("https://localhost/callback")).toBe(false);
  });
});
