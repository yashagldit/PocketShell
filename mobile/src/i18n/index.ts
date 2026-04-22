import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import * as Localization from "expo-localization";
import { getAppLocale, setAppLocale } from "@/services/secureStore";

const NS_FILES = [
  "common",
  "tabs",
  "auth",
  "onboarding",
  "pairing",
  "hosts",
  "monitor",
  "terminal",
  "files",
  "workspace",
  "workspaces",
  "process",
  "agentChat",
  "agentSessions",
  "alerts",
  "security",
  "sessions",
  "newChat",
  "settings",
  "dialogs",
  "widgets",
  "notifications",
  "stats",
] as const;

export const NAMESPACES = NS_FILES;

// English — full catalog, source of truth and fallback for all other locales.
import enCommon from "@/locales/en/common.json";
import enTabs from "@/locales/en/tabs.json";
import enAuth from "@/locales/en/auth.json";
import enOnboarding from "@/locales/en/onboarding.json";
import enPairing from "@/locales/en/pairing.json";
import enHosts from "@/locales/en/hosts.json";
import enMonitor from "@/locales/en/monitor.json";
import enTerminal from "@/locales/en/terminal.json";
import enFiles from "@/locales/en/files.json";
import enWorkspace from "@/locales/en/workspace.json";
import enWorkspaces from "@/locales/en/workspaces.json";
import enProcess from "@/locales/en/process.json";
import enAgentChat from "@/locales/en/agentChat.json";
import enAgentSessions from "@/locales/en/agentSessions.json";
import enAlerts from "@/locales/en/alerts.json";
import enSecurity from "@/locales/en/security.json";
import enSessions from "@/locales/en/sessions.json";
import enNewChat from "@/locales/en/newChat.json";
import enSettings from "@/locales/en/settings.json";
import enDialogs from "@/locales/en/dialogs.json";
import enWidgets from "@/locales/en/widgets.json";
import enNotifications from "@/locales/en/notifications.json";
import enStats from "@/locales/en/stats.json";

import deCommon from "@/locales/de/common.json";
import deTabs from "@/locales/de/tabs.json";
import deAuth from "@/locales/de/auth.json";
import deOnboarding from "@/locales/de/onboarding.json";
import dePairing from "@/locales/de/pairing.json";
import deHosts from "@/locales/de/hosts.json";
import deMonitor from "@/locales/de/monitor.json";
import deTerminal from "@/locales/de/terminal.json";
import deFiles from "@/locales/de/files.json";
import deWorkspace from "@/locales/de/workspace.json";
import deWorkspaces from "@/locales/de/workspaces.json";
import deProcess from "@/locales/de/process.json";
import deAgentChat from "@/locales/de/agentChat.json";
import deAgentSessions from "@/locales/de/agentSessions.json";
import deAlerts from "@/locales/de/alerts.json";
import deSecurity from "@/locales/de/security.json";
import deSessions from "@/locales/de/sessions.json";
import deNewChat from "@/locales/de/newChat.json";
import deSettings from "@/locales/de/settings.json";
import deDialogs from "@/locales/de/dialogs.json";
import deWidgets from "@/locales/de/widgets.json";
import deNotifications from "@/locales/de/notifications.json";
import deStats from "@/locales/de/stats.json";

import jaCommon from "@/locales/ja/common.json";
import jaTabs from "@/locales/ja/tabs.json";
import jaAuth from "@/locales/ja/auth.json";
import jaOnboarding from "@/locales/ja/onboarding.json";
import jaPairing from "@/locales/ja/pairing.json";
import jaHosts from "@/locales/ja/hosts.json";
import jaMonitor from "@/locales/ja/monitor.json";
import jaTerminal from "@/locales/ja/terminal.json";
import jaFiles from "@/locales/ja/files.json";
import jaWorkspace from "@/locales/ja/workspace.json";
import jaWorkspaces from "@/locales/ja/workspaces.json";
import jaProcess from "@/locales/ja/process.json";
import jaAgentChat from "@/locales/ja/agentChat.json";
import jaAgentSessions from "@/locales/ja/agentSessions.json";
import jaAlerts from "@/locales/ja/alerts.json";
import jaSecurity from "@/locales/ja/security.json";
import jaSessions from "@/locales/ja/sessions.json";
import jaNewChat from "@/locales/ja/newChat.json";
import jaSettings from "@/locales/ja/settings.json";
import jaDialogs from "@/locales/ja/dialogs.json";
import jaWidgets from "@/locales/ja/widgets.json";
import jaNotifications from "@/locales/ja/notifications.json";
import jaStats from "@/locales/ja/stats.json";

import hiCommon from "@/locales/hi/common.json";
import hiTabs from "@/locales/hi/tabs.json";
import hiAuth from "@/locales/hi/auth.json";
import hiOnboarding from "@/locales/hi/onboarding.json";
import hiPairing from "@/locales/hi/pairing.json";
import hiHosts from "@/locales/hi/hosts.json";
import hiMonitor from "@/locales/hi/monitor.json";
import hiTerminal from "@/locales/hi/terminal.json";
import hiFiles from "@/locales/hi/files.json";
import hiWorkspace from "@/locales/hi/workspace.json";
import hiWorkspaces from "@/locales/hi/workspaces.json";
import hiProcess from "@/locales/hi/process.json";
import hiAgentChat from "@/locales/hi/agentChat.json";
import hiAgentSessions from "@/locales/hi/agentSessions.json";
import hiAlerts from "@/locales/hi/alerts.json";
import hiSecurity from "@/locales/hi/security.json";
import hiSessions from "@/locales/hi/sessions.json";
import hiNewChat from "@/locales/hi/newChat.json";
import hiSettings from "@/locales/hi/settings.json";
import hiDialogs from "@/locales/hi/dialogs.json";
import hiWidgets from "@/locales/hi/widgets.json";
import hiNotifications from "@/locales/hi/notifications.json";
import hiStats from "@/locales/hi/stats.json";

export const SUPPORTED_LOCALES = ["en", "de", "ja", "hi"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: SupportedLocale = "en";

export const LOCALE_LABELS: Record<SupportedLocale, string> = {
  en: "English",
  de: "Deutsch",
  ja: "日本語",
  hi: "हिन्दी",
};

const resources = {
  en: {
    common: enCommon,
    tabs: enTabs,
    auth: enAuth,
    onboarding: enOnboarding,
    pairing: enPairing,
    hosts: enHosts,
    monitor: enMonitor,
    terminal: enTerminal,
    files: enFiles,
    workspace: enWorkspace,
    workspaces: enWorkspaces,
    process: enProcess,
    agentChat: enAgentChat,
    agentSessions: enAgentSessions,
    alerts: enAlerts,
    security: enSecurity,
    sessions: enSessions,
    newChat: enNewChat,
    settings: enSettings,
    dialogs: enDialogs,
    widgets: enWidgets,
    notifications: enNotifications,
    stats: enStats,
  },
  de: {
    common: deCommon,
    tabs: deTabs,
    auth: deAuth,
    onboarding: deOnboarding,
    pairing: dePairing,
    hosts: deHosts,
    monitor: deMonitor,
    terminal: deTerminal,
    files: deFiles,
    workspace: deWorkspace,
    workspaces: deWorkspaces,
    process: deProcess,
    agentChat: deAgentChat,
    agentSessions: deAgentSessions,
    alerts: deAlerts,
    security: deSecurity,
    sessions: deSessions,
    newChat: deNewChat,
    settings: deSettings,
    dialogs: deDialogs,
    widgets: deWidgets,
    notifications: deNotifications,
    stats: deStats,
  },
  ja: {
    common: jaCommon,
    tabs: jaTabs,
    auth: jaAuth,
    onboarding: jaOnboarding,
    pairing: jaPairing,
    hosts: jaHosts,
    monitor: jaMonitor,
    terminal: jaTerminal,
    files: jaFiles,
    workspace: jaWorkspace,
    workspaces: jaWorkspaces,
    process: jaProcess,
    agentChat: jaAgentChat,
    agentSessions: jaAgentSessions,
    alerts: jaAlerts,
    security: jaSecurity,
    sessions: jaSessions,
    newChat: jaNewChat,
    settings: jaSettings,
    dialogs: jaDialogs,
    widgets: jaWidgets,
    notifications: jaNotifications,
    stats: jaStats,
  },
  hi: {
    common: hiCommon,
    tabs: hiTabs,
    auth: hiAuth,
    onboarding: hiOnboarding,
    pairing: hiPairing,
    hosts: hiHosts,
    monitor: hiMonitor,
    terminal: hiTerminal,
    files: hiFiles,
    workspace: hiWorkspace,
    workspaces: hiWorkspaces,
    process: hiProcess,
    agentChat: hiAgentChat,
    agentSessions: hiAgentSessions,
    alerts: hiAlerts,
    security: hiSecurity,
    sessions: hiSessions,
    newChat: hiNewChat,
    settings: hiSettings,
    dialogs: hiDialogs,
    widgets: hiWidgets,
    notifications: hiNotifications,
    stats: hiStats,
  },
} as const;

function resolveDeviceLocale(): SupportedLocale {
  const tags = Localization.getLocales();
  for (const tag of tags) {
    const code = (tag.languageCode ?? "").toLowerCase();
    if ((SUPPORTED_LOCALES as readonly string[]).includes(code)) {
      return code as SupportedLocale;
    }
  }
  return DEFAULT_LOCALE;
}

let initPromise: Promise<typeof i18n> | null = null;

export function initI18n(): Promise<typeof i18n> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const override = await getAppLocale();
    const lng =
      override && (SUPPORTED_LOCALES as readonly string[]).includes(override)
        ? (override as SupportedLocale)
        : resolveDeviceLocale();

    await i18n.use(initReactI18next).init({
      resources: resources as any,
      lng,
      fallbackLng: DEFAULT_LOCALE,
      defaultNS: "common",
      ns: NAMESPACES as unknown as string[],
      interpolation: { escapeValue: false },
      returnNull: false,
      compatibilityJSON: "v4",
    });
    return i18n;
  })();
  return initPromise;
}

export async function changeLocale(locale: SupportedLocale): Promise<void> {
  await setAppLocale(locale);
  await i18n.changeLanguage(locale);
}

export default i18n;
