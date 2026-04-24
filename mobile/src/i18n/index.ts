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


import frCommon from "@/locales/fr/common.json";
import frTabs from "@/locales/fr/tabs.json";
import frAuth from "@/locales/fr/auth.json";
import frOnboarding from "@/locales/fr/onboarding.json";
import frPairing from "@/locales/fr/pairing.json";
import frHosts from "@/locales/fr/hosts.json";
import frMonitor from "@/locales/fr/monitor.json";
import frTerminal from "@/locales/fr/terminal.json";
import frFiles from "@/locales/fr/files.json";
import frWorkspace from "@/locales/fr/workspace.json";
import frWorkspaces from "@/locales/fr/workspaces.json";
import frProcess from "@/locales/fr/process.json";
import frAgentChat from "@/locales/fr/agentChat.json";
import frAgentSessions from "@/locales/fr/agentSessions.json";
import frAlerts from "@/locales/fr/alerts.json";
import frSecurity from "@/locales/fr/security.json";
import frSessions from "@/locales/fr/sessions.json";
import frNewChat from "@/locales/fr/newChat.json";
import frSettings from "@/locales/fr/settings.json";
import frDialogs from "@/locales/fr/dialogs.json";
import frWidgets from "@/locales/fr/widgets.json";
import frNotifications from "@/locales/fr/notifications.json";
import frStats from "@/locales/fr/stats.json";

import koCommon from "@/locales/ko/common.json";
import koTabs from "@/locales/ko/tabs.json";
import koAuth from "@/locales/ko/auth.json";
import koOnboarding from "@/locales/ko/onboarding.json";
import koPairing from "@/locales/ko/pairing.json";
import koHosts from "@/locales/ko/hosts.json";
import koMonitor from "@/locales/ko/monitor.json";
import koTerminal from "@/locales/ko/terminal.json";
import koFiles from "@/locales/ko/files.json";
import koWorkspace from "@/locales/ko/workspace.json";
import koWorkspaces from "@/locales/ko/workspaces.json";
import koProcess from "@/locales/ko/process.json";
import koAgentChat from "@/locales/ko/agentChat.json";
import koAgentSessions from "@/locales/ko/agentSessions.json";
import koAlerts from "@/locales/ko/alerts.json";
import koSecurity from "@/locales/ko/security.json";
import koSessions from "@/locales/ko/sessions.json";
import koNewChat from "@/locales/ko/newChat.json";
import koSettings from "@/locales/ko/settings.json";
import koDialogs from "@/locales/ko/dialogs.json";
import koWidgets from "@/locales/ko/widgets.json";
import koNotifications from "@/locales/ko/notifications.json";
import koStats from "@/locales/ko/stats.json";

import zhCNCommon from "@/locales/zh-CN/common.json";
import zhCNTabs from "@/locales/zh-CN/tabs.json";
import zhCNAuth from "@/locales/zh-CN/auth.json";
import zhCNOnboarding from "@/locales/zh-CN/onboarding.json";
import zhCNPairing from "@/locales/zh-CN/pairing.json";
import zhCNHosts from "@/locales/zh-CN/hosts.json";
import zhCNMonitor from "@/locales/zh-CN/monitor.json";
import zhCNTerminal from "@/locales/zh-CN/terminal.json";
import zhCNFiles from "@/locales/zh-CN/files.json";
import zhCNWorkspace from "@/locales/zh-CN/workspace.json";
import zhCNWorkspaces from "@/locales/zh-CN/workspaces.json";
import zhCNProcess from "@/locales/zh-CN/process.json";
import zhCNAgentChat from "@/locales/zh-CN/agentChat.json";
import zhCNAgentSessions from "@/locales/zh-CN/agentSessions.json";
import zhCNAlerts from "@/locales/zh-CN/alerts.json";
import zhCNSecurity from "@/locales/zh-CN/security.json";
import zhCNSessions from "@/locales/zh-CN/sessions.json";
import zhCNNewChat from "@/locales/zh-CN/newChat.json";
import zhCNSettings from "@/locales/zh-CN/settings.json";
import zhCNDialogs from "@/locales/zh-CN/dialogs.json";
import zhCNWidgets from "@/locales/zh-CN/widgets.json";
import zhCNNotifications from "@/locales/zh-CN/notifications.json";
import zhCNStats from "@/locales/zh-CN/stats.json";

import zhTWCommon from "@/locales/zh-TW/common.json";
import zhTWTabs from "@/locales/zh-TW/tabs.json";
import zhTWAuth from "@/locales/zh-TW/auth.json";
import zhTWOnboarding from "@/locales/zh-TW/onboarding.json";
import zhTWPairing from "@/locales/zh-TW/pairing.json";
import zhTWHosts from "@/locales/zh-TW/hosts.json";
import zhTWMonitor from "@/locales/zh-TW/monitor.json";
import zhTWTerminal from "@/locales/zh-TW/terminal.json";
import zhTWFiles from "@/locales/zh-TW/files.json";
import zhTWWorkspace from "@/locales/zh-TW/workspace.json";
import zhTWWorkspaces from "@/locales/zh-TW/workspaces.json";
import zhTWProcess from "@/locales/zh-TW/process.json";
import zhTWAgentChat from "@/locales/zh-TW/agentChat.json";
import zhTWAgentSessions from "@/locales/zh-TW/agentSessions.json";
import zhTWAlerts from "@/locales/zh-TW/alerts.json";
import zhTWSecurity from "@/locales/zh-TW/security.json";
import zhTWSessions from "@/locales/zh-TW/sessions.json";
import zhTWNewChat from "@/locales/zh-TW/newChat.json";
import zhTWSettings from "@/locales/zh-TW/settings.json";
import zhTWDialogs from "@/locales/zh-TW/dialogs.json";
import zhTWWidgets from "@/locales/zh-TW/widgets.json";
import zhTWNotifications from "@/locales/zh-TW/notifications.json";
import zhTWStats from "@/locales/zh-TW/stats.json";

import esCommon from "@/locales/es/common.json";
import esTabs from "@/locales/es/tabs.json";
import esAuth from "@/locales/es/auth.json";
import esOnboarding from "@/locales/es/onboarding.json";
import esPairing from "@/locales/es/pairing.json";
import esHosts from "@/locales/es/hosts.json";
import esMonitor from "@/locales/es/monitor.json";
import esTerminal from "@/locales/es/terminal.json";
import esFiles from "@/locales/es/files.json";
import esWorkspace from "@/locales/es/workspace.json";
import esWorkspaces from "@/locales/es/workspaces.json";
import esProcess from "@/locales/es/process.json";
import esAgentChat from "@/locales/es/agentChat.json";
import esAgentSessions from "@/locales/es/agentSessions.json";
import esAlerts from "@/locales/es/alerts.json";
import esSecurity from "@/locales/es/security.json";
import esSessions from "@/locales/es/sessions.json";
import esNewChat from "@/locales/es/newChat.json";
import esSettings from "@/locales/es/settings.json";
import esDialogs from "@/locales/es/dialogs.json";
import esWidgets from "@/locales/es/widgets.json";
import esNotifications from "@/locales/es/notifications.json";
import esStats from "@/locales/es/stats.json";

import itCommon from "@/locales/it/common.json";
import itTabs from "@/locales/it/tabs.json";
import itAuth from "@/locales/it/auth.json";
import itOnboarding from "@/locales/it/onboarding.json";
import itPairing from "@/locales/it/pairing.json";
import itHosts from "@/locales/it/hosts.json";
import itMonitor from "@/locales/it/monitor.json";
import itTerminal from "@/locales/it/terminal.json";
import itFiles from "@/locales/it/files.json";
import itWorkspace from "@/locales/it/workspace.json";
import itWorkspaces from "@/locales/it/workspaces.json";
import itProcess from "@/locales/it/process.json";
import itAgentChat from "@/locales/it/agentChat.json";
import itAgentSessions from "@/locales/it/agentSessions.json";
import itAlerts from "@/locales/it/alerts.json";
import itSecurity from "@/locales/it/security.json";
import itSessions from "@/locales/it/sessions.json";
import itNewChat from "@/locales/it/newChat.json";
import itSettings from "@/locales/it/settings.json";
import itDialogs from "@/locales/it/dialogs.json";
import itWidgets from "@/locales/it/widgets.json";
import itNotifications from "@/locales/it/notifications.json";
import itStats from "@/locales/it/stats.json";

import ruCommon from "@/locales/ru/common.json";
import ruTabs from "@/locales/ru/tabs.json";
import ruAuth from "@/locales/ru/auth.json";
import ruOnboarding from "@/locales/ru/onboarding.json";
import ruPairing from "@/locales/ru/pairing.json";
import ruHosts from "@/locales/ru/hosts.json";
import ruMonitor from "@/locales/ru/monitor.json";
import ruTerminal from "@/locales/ru/terminal.json";
import ruFiles from "@/locales/ru/files.json";
import ruWorkspace from "@/locales/ru/workspace.json";
import ruWorkspaces from "@/locales/ru/workspaces.json";
import ruProcess from "@/locales/ru/process.json";
import ruAgentChat from "@/locales/ru/agentChat.json";
import ruAgentSessions from "@/locales/ru/agentSessions.json";
import ruAlerts from "@/locales/ru/alerts.json";
import ruSecurity from "@/locales/ru/security.json";
import ruSessions from "@/locales/ru/sessions.json";
import ruNewChat from "@/locales/ru/newChat.json";
import ruSettings from "@/locales/ru/settings.json";
import ruDialogs from "@/locales/ru/dialogs.json";
import ruWidgets from "@/locales/ru/widgets.json";
import ruNotifications from "@/locales/ru/notifications.json";
import ruStats from "@/locales/ru/stats.json";

import ptBRCommon from "@/locales/pt-BR/common.json";
import ptBRTabs from "@/locales/pt-BR/tabs.json";
import ptBRAuth from "@/locales/pt-BR/auth.json";
import ptBROnboarding from "@/locales/pt-BR/onboarding.json";
import ptBRPairing from "@/locales/pt-BR/pairing.json";
import ptBRHosts from "@/locales/pt-BR/hosts.json";
import ptBRMonitor from "@/locales/pt-BR/monitor.json";
import ptBRTerminal from "@/locales/pt-BR/terminal.json";
import ptBRFiles from "@/locales/pt-BR/files.json";
import ptBRWorkspace from "@/locales/pt-BR/workspace.json";
import ptBRWorkspaces from "@/locales/pt-BR/workspaces.json";
import ptBRProcess from "@/locales/pt-BR/process.json";
import ptBRAgentChat from "@/locales/pt-BR/agentChat.json";
import ptBRAgentSessions from "@/locales/pt-BR/agentSessions.json";
import ptBRAlerts from "@/locales/pt-BR/alerts.json";
import ptBRSecurity from "@/locales/pt-BR/security.json";
import ptBRSessions from "@/locales/pt-BR/sessions.json";
import ptBRNewChat from "@/locales/pt-BR/newChat.json";
import ptBRSettings from "@/locales/pt-BR/settings.json";
import ptBRDialogs from "@/locales/pt-BR/dialogs.json";
import ptBRWidgets from "@/locales/pt-BR/widgets.json";
import ptBRNotifications from "@/locales/pt-BR/notifications.json";
import ptBRStats from "@/locales/pt-BR/stats.json";

export const SUPPORTED_LOCALES = ["en", "de", "ja", "hi", "fr", "ko", "zh-CN", "zh-TW", "es", "it", "ru", "pt-BR"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: SupportedLocale = "en";

export const LOCALE_LABELS: Record<SupportedLocale, string> = {
  en: "English",
  de: "Deutsch",
  ja: "日本語",
  hi: "हिन्दी",
  fr: "Français",
  ko: "한국어",
  "zh-CN": "简体中文",
  "zh-TW": "繁體中文",
  es: "Español",
  it: "Italiano",
  ru: "Русский",
  "pt-BR": "Português (Brasil)",
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
  "fr": {
    common: frCommon,
    tabs: frTabs,
    auth: frAuth,
    onboarding: frOnboarding,
    pairing: frPairing,
    hosts: frHosts,
    monitor: frMonitor,
    terminal: frTerminal,
    files: frFiles,
    workspace: frWorkspace,
    workspaces: frWorkspaces,
    process: frProcess,
    agentChat: frAgentChat,
    agentSessions: frAgentSessions,
    alerts: frAlerts,
    security: frSecurity,
    sessions: frSessions,
    newChat: frNewChat,
    settings: frSettings,
    dialogs: frDialogs,
    widgets: frWidgets,
    notifications: frNotifications,
    stats: frStats,
  },
  "ko": {
    common: koCommon,
    tabs: koTabs,
    auth: koAuth,
    onboarding: koOnboarding,
    pairing: koPairing,
    hosts: koHosts,
    monitor: koMonitor,
    terminal: koTerminal,
    files: koFiles,
    workspace: koWorkspace,
    workspaces: koWorkspaces,
    process: koProcess,
    agentChat: koAgentChat,
    agentSessions: koAgentSessions,
    alerts: koAlerts,
    security: koSecurity,
    sessions: koSessions,
    newChat: koNewChat,
    settings: koSettings,
    dialogs: koDialogs,
    widgets: koWidgets,
    notifications: koNotifications,
    stats: koStats,
  },
  "zh-CN": {
    common: zhCNCommon,
    tabs: zhCNTabs,
    auth: zhCNAuth,
    onboarding: zhCNOnboarding,
    pairing: zhCNPairing,
    hosts: zhCNHosts,
    monitor: zhCNMonitor,
    terminal: zhCNTerminal,
    files: zhCNFiles,
    workspace: zhCNWorkspace,
    workspaces: zhCNWorkspaces,
    process: zhCNProcess,
    agentChat: zhCNAgentChat,
    agentSessions: zhCNAgentSessions,
    alerts: zhCNAlerts,
    security: zhCNSecurity,
    sessions: zhCNSessions,
    newChat: zhCNNewChat,
    settings: zhCNSettings,
    dialogs: zhCNDialogs,
    widgets: zhCNWidgets,
    notifications: zhCNNotifications,
    stats: zhCNStats,
  },
  "zh-TW": {
    common: zhTWCommon,
    tabs: zhTWTabs,
    auth: zhTWAuth,
    onboarding: zhTWOnboarding,
    pairing: zhTWPairing,
    hosts: zhTWHosts,
    monitor: zhTWMonitor,
    terminal: zhTWTerminal,
    files: zhTWFiles,
    workspace: zhTWWorkspace,
    workspaces: zhTWWorkspaces,
    process: zhTWProcess,
    agentChat: zhTWAgentChat,
    agentSessions: zhTWAgentSessions,
    alerts: zhTWAlerts,
    security: zhTWSecurity,
    sessions: zhTWSessions,
    newChat: zhTWNewChat,
    settings: zhTWSettings,
    dialogs: zhTWDialogs,
    widgets: zhTWWidgets,
    notifications: zhTWNotifications,
    stats: zhTWStats,
  },
  "es": {
    common: esCommon,
    tabs: esTabs,
    auth: esAuth,
    onboarding: esOnboarding,
    pairing: esPairing,
    hosts: esHosts,
    monitor: esMonitor,
    terminal: esTerminal,
    files: esFiles,
    workspace: esWorkspace,
    workspaces: esWorkspaces,
    process: esProcess,
    agentChat: esAgentChat,
    agentSessions: esAgentSessions,
    alerts: esAlerts,
    security: esSecurity,
    sessions: esSessions,
    newChat: esNewChat,
    settings: esSettings,
    dialogs: esDialogs,
    widgets: esWidgets,
    notifications: esNotifications,
    stats: esStats,
  },
  "it": {
    common: itCommon,
    tabs: itTabs,
    auth: itAuth,
    onboarding: itOnboarding,
    pairing: itPairing,
    hosts: itHosts,
    monitor: itMonitor,
    terminal: itTerminal,
    files: itFiles,
    workspace: itWorkspace,
    workspaces: itWorkspaces,
    process: itProcess,
    agentChat: itAgentChat,
    agentSessions: itAgentSessions,
    alerts: itAlerts,
    security: itSecurity,
    sessions: itSessions,
    newChat: itNewChat,
    settings: itSettings,
    dialogs: itDialogs,
    widgets: itWidgets,
    notifications: itNotifications,
    stats: itStats,
  },
  "ru": {
    common: ruCommon,
    tabs: ruTabs,
    auth: ruAuth,
    onboarding: ruOnboarding,
    pairing: ruPairing,
    hosts: ruHosts,
    monitor: ruMonitor,
    terminal: ruTerminal,
    files: ruFiles,
    workspace: ruWorkspace,
    workspaces: ruWorkspaces,
    process: ruProcess,
    agentChat: ruAgentChat,
    agentSessions: ruAgentSessions,
    alerts: ruAlerts,
    security: ruSecurity,
    sessions: ruSessions,
    newChat: ruNewChat,
    settings: ruSettings,
    dialogs: ruDialogs,
    widgets: ruWidgets,
    notifications: ruNotifications,
    stats: ruStats,
  },
  "pt-BR": {
    common: ptBRCommon,
    tabs: ptBRTabs,
    auth: ptBRAuth,
    onboarding: ptBROnboarding,
    pairing: ptBRPairing,
    hosts: ptBRHosts,
    monitor: ptBRMonitor,
    terminal: ptBRTerminal,
    files: ptBRFiles,
    workspace: ptBRWorkspace,
    workspaces: ptBRWorkspaces,
    process: ptBRProcess,
    agentChat: ptBRAgentChat,
    agentSessions: ptBRAgentSessions,
    alerts: ptBRAlerts,
    security: ptBRSecurity,
    sessions: ptBRSessions,
    newChat: ptBRNewChat,
    settings: ptBRSettings,
    dialogs: ptBRDialogs,
    widgets: ptBRWidgets,
    notifications: ptBRNotifications,
    stats: ptBRStats,
  },
} as const;

function resolveDeviceLocale(): SupportedLocale {
  const tags = Localization.getLocales();
  const supported = SUPPORTED_LOCALES as readonly string[];
  for (const tag of tags) {
    const fullTag = tag.languageTag; // e.g. "zh-CN", "pt-BR"
    const langCode = tag.languageCode?.toLowerCase() ?? ""; // e.g. "zh", "pt"

    if (supported.includes(fullTag)) {
      return fullTag as SupportedLocale;
    }
    if (supported.includes(langCode)) {
      return langCode as SupportedLocale;
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
