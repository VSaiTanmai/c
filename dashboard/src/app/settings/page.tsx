"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Settings as SettingsIcon,
  Bell,
  Shield,
  Palette,
  Database,
  Clock,
  Save,
  RotateCcw,
  Monitor,
  Moon,
  Sun,
  Volume2,
  VolumeX,
  Key,
  Globe,
  AlertTriangle,
  Brain,
  Crosshair,
  Search as SearchIcon,
  ShieldCheck,
  Zap,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

interface SettingsState {
  general: {
    orgName: string;
    timezone: string;
    language: string;
    dateFormat: string;
  };
  notifications: {
    criticalAlerts: boolean;
    highAlerts: boolean;
    mediumAlerts: boolean;
    emailDigest: boolean;
    soundEnabled: boolean;
    desktopNotifications: boolean;
  };
  security: {
    sessionTimeout: number;
    mfaEnabled: boolean;
    apiKeyRotation: number;
    auditLogRetention: number;
  };
  data: {
    retentionDays: number;
    autoArchive: boolean;
    compressionEnabled: boolean;
    maxBatchSize: number;
  };
  aiPipeline: {
    triageThreshold: number;
    hunterCorrelationMin: number;
    verifierConfidenceMin: number;
    hmacEnabled: boolean;
    autoInvestigation: boolean;
    maxConcurrentAgents: number;
    driftAlertThreshold: number;
    xaiEnabled: boolean;
  };
}

function Toggle({
  enabled,
  onChange,
  label,
  description,
}: {
  enabled: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description?: string;
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <p className="text-sm font-medium text-foreground">{label}</p>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </div>
      <button
        onClick={() => onChange(!enabled)}
        className={cn(
          "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
          enabled ? "bg-primary" : "bg-muted"
        )}
      >
        <span
          className={cn(
            "inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform",
            enabled ? "translate-x-[18px]" : "translate-x-[3px]"
          )}
        />
      </button>
    </div>
  );
}

export default function SettingsPage() {
  const [tab, setTab] = useState("general");
  const [saved, setSaved] = useState(false);

  const [settings, setSettings] = useState<SettingsState>({
    general: {
      orgName: "CLIF Security Operations",
      timezone: "UTC",
      language: "en-US",
      dateFormat: "YYYY-MM-DD HH:mm:ss",
    },
    notifications: {
      criticalAlerts: true,
      highAlerts: true,
      mediumAlerts: false,
      emailDigest: true,
      soundEnabled: true,
      desktopNotifications: true,
    },
    security: {
      sessionTimeout: 30,
      mfaEnabled: true,
      apiKeyRotation: 90,
      auditLogRetention: 365,
    },
    data: {
      retentionDays: 90,
      autoArchive: true,
      compressionEnabled: true,
      maxBatchSize: 10000,
    },
    aiPipeline: {
      triageThreshold: 0.65,
      hunterCorrelationMin: 0.4,
      verifierConfidenceMin: 0.7,
      hmacEnabled: true,
      autoInvestigation: true,
      maxConcurrentAgents: 3,
      driftAlertThreshold: 0.1,
      xaiEnabled: true,
    },
  });

  const updateGeneral = (field: keyof SettingsState["general"], value: string) => {
    setSettings((s) => ({
      ...s,
      general: { ...s.general, [field]: value },
    }));
    setSaved(false);
  };

  const updateNotifications = (field: keyof SettingsState["notifications"], value: boolean) => {
    setSettings((s) => ({
      ...s,
      notifications: { ...s.notifications, [field]: value },
    }));
    setSaved(false);
  };

  const updateSecurity = (field: keyof SettingsState["security"], value: number | boolean) => {
    setSettings((s) => ({
      ...s,
      security: { ...s.security, [field]: value },
    }));
    setSaved(false);
  };

  const updateData = (field: keyof SettingsState["data"], value: number | boolean) => {
    setSettings((s) => ({
      ...s,
      data: { ...s.data, [field]: value },
    }));
    setSaved(false);
  };

  const updateAI = (field: keyof SettingsState["aiPipeline"], value: number | boolean) => {
    setSettings((s) => ({
      ...s,
      aiPipeline: { ...s.aiPipeline, [field]: value },
    }));
    setSaved(false);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <SettingsIcon className="h-5 w-5 text-primary" />
            Settings
          </h2>
          <p className="text-sm text-muted-foreground">
            Configure CLIF platform preferences and security policies
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saved && (
            <Badge variant="success" className="text-xs">Saved</Badge>
          )}
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>
            <RotateCcw className="mr-1 h-3 w-3" /> Reset
          </Button>
          <Button size="sm" onClick={handleSave}>
            <Save className="mr-1 h-3 w-3" /> Save Changes
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="general">
            <Monitor className="mr-1 h-3 w-3" /> General
          </TabsTrigger>
          <TabsTrigger value="notifications">
            <Bell className="mr-1 h-3 w-3" /> Notifications
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="mr-1 h-3 w-3" /> Security
          </TabsTrigger>
          <TabsTrigger value="data">
            <Database className="mr-1 h-3 w-3" /> Data
          </TabsTrigger>
          <TabsTrigger value="ai-pipeline">
            <Brain className="mr-1 h-3 w-3" /> AI Pipeline
          </TabsTrigger>
        </TabsList>

        {/* General */}
        <TabsContent value="general" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Organization</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Organization Name
                  </label>
                  <Input
                    value={settings.general.orgName}
                    onChange={(e) => updateGeneral("orgName", e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Timezone
                  </label>
                  <Input
                    value={settings.general.timezone}
                    onChange={(e) => updateGeneral("timezone", e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Language
                  </label>
                  <Input
                    value={settings.general.language}
                    onChange={(e) => updateGeneral("language", e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Date Format
                  </label>
                  <Input
                    value={settings.general.dateFormat}
                    onChange={(e) => updateGeneral("dateFormat", e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Notifications */}
        <TabsContent value="notifications" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Alert Notifications</CardTitle>
              <CardDescription>Configure which alerts trigger notifications</CardDescription>
            </CardHeader>
            <CardContent>
              <Toggle
                label="Critical Alerts"
                description="Immediate notification for critical severity events"
                enabled={settings.notifications.criticalAlerts}
                onChange={(v) => updateNotifications("criticalAlerts", v)}
              />
              <Separator />
              <Toggle
                label="High Alerts"
                description="Notification for high severity events"
                enabled={settings.notifications.highAlerts}
                onChange={(v) => updateNotifications("highAlerts", v)}
              />
              <Separator />
              <Toggle
                label="Medium Alerts"
                description="Notification for medium severity events"
                enabled={settings.notifications.mediumAlerts}
                onChange={(v) => updateNotifications("mediumAlerts", v)}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Delivery Preferences</CardTitle>
            </CardHeader>
            <CardContent>
              <Toggle
                label="Email Digest"
                description="Daily email summary of alerts and investigations"
                enabled={settings.notifications.emailDigest}
                onChange={(v) => updateNotifications("emailDigest", v)}
              />
              <Separator />
              <Toggle
                label="Sound Notifications"
                description="Play sound for new alerts"
                enabled={settings.notifications.soundEnabled}
                onChange={(v) => updateNotifications("soundEnabled", v)}
              />
              <Separator />
              <Toggle
                label="Desktop Notifications"
                description="Show browser push notifications"
                enabled={settings.notifications.desktopNotifications}
                onChange={(v) => updateNotifications("desktopNotifications", v)}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security */}
        <TabsContent value="security" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Security Policies</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Session Timeout (minutes)
                  </label>
                  <Input
                    type="number"
                    value={settings.security.sessionTimeout}
                    onChange={(e) =>
                      updateSecurity("sessionTimeout", parseInt(e.target.value) || 30)
                    }
                    className="mt-1"
                    min={5}
                    max={480}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    API Key Rotation (days)
                  </label>
                  <Input
                    type="number"
                    value={settings.security.apiKeyRotation}
                    onChange={(e) =>
                      updateSecurity("apiKeyRotation", parseInt(e.target.value) || 90)
                    }
                    className="mt-1"
                    min={7}
                    max={365}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Audit Log Retention (days)
                  </label>
                  <Input
                    type="number"
                    value={settings.security.auditLogRetention}
                    onChange={(e) =>
                      updateSecurity("auditLogRetention", parseInt(e.target.value) || 365)
                    }
                    className="mt-1"
                    min={30}
                  />
                </div>
              </div>
              <Separator />
              <Toggle
                label="Multi-Factor Authentication"
                description="Require MFA for all user accounts"
                enabled={settings.security.mfaEnabled}
                onChange={(v) => updateSecurity("mfaEnabled", v)}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* Data */}
        <TabsContent value="data" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Data Management</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Event Retention (days)
                  </label>
                  <Input
                    type="number"
                    value={settings.data.retentionDays}
                    onChange={(e) =>
                      updateData("retentionDays", parseInt(e.target.value) || 90)
                    }
                    className="mt-1"
                    min={7}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">
                    Max Batch Size
                  </label>
                  <Input
                    type="number"
                    value={settings.data.maxBatchSize}
                    onChange={(e) =>
                      updateData("maxBatchSize", parseInt(e.target.value) || 10000)
                    }
                    className="mt-1"
                    min={100}
                    max={100000}
                  />
                </div>
              </div>
              <Separator />
              <Toggle
                label="Auto-Archive"
                description="Automatically archive evidence batches older than retention period"
                enabled={settings.data.autoArchive}
                onChange={(v) => updateData("autoArchive", v)}
              />
              <Separator />
              <Toggle
                label="Compression"
                description="Enable compression for stored events and evidence"
                enabled={settings.data.compressionEnabled}
                onChange={(v) => updateData("compressionEnabled", v)}
              />
            </CardContent>
          </Card>

          <Card className="border-amber-500/20">
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-foreground">Danger Zone</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Purging data is irreversible. Export your data before proceeding.
                  </p>
                  <Button variant="destructive" size="sm" className="mt-3 text-xs" disabled>
                    Purge All Event Data
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Pipeline */}
        <TabsContent value="ai-pipeline" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm">Agent Thresholds</CardTitle>
                  <CardDescription>Configure classification and correlation thresholds for each agent</CardDescription>
                </div>
                <Link href="/ai-agents">
                  <Button variant="ghost" size="sm" className="text-xs">
                    View Agents <ChevronRight className="ml-1 h-3 w-3" />
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="rounded-lg border border-amber-500/20 p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <Crosshair className="h-3.5 w-3.5 text-amber-400" />
                    <span className="text-xs font-medium text-foreground">Triage Agent</span>
                  </div>
                  <div>
                    <label className="text-2xs text-muted-foreground">Classification Threshold</label>
                    <Input
                      type="number"
                      step="0.05"
                      min={0}
                      max={1}
                      value={settings.aiPipeline.triageThreshold}
                      onChange={(e) => updateAI("triageThreshold", parseFloat(e.target.value) || 0.65)}
                      className="mt-1 h-8 text-xs"
                    />
                  </div>
                </div>

                <div className="rounded-lg border border-cyan-500/20 p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <SearchIcon className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-medium text-foreground">Hunter Agent</span>
                  </div>
                  <div>
                    <label className="text-2xs text-muted-foreground">Correlation Minimum</label>
                    <Input
                      type="number"
                      step="0.05"
                      min={0}
                      max={1}
                      value={settings.aiPipeline.hunterCorrelationMin}
                      onChange={(e) => updateAI("hunterCorrelationMin", parseFloat(e.target.value) || 0.4)}
                      className="mt-1 h-8 text-xs"
                    />
                  </div>
                </div>

                <div className="rounded-lg border border-emerald-500/20 p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-xs font-medium text-foreground">Verifier Agent</span>
                  </div>
                  <div>
                    <label className="text-2xs text-muted-foreground">Confidence Minimum</label>
                    <Input
                      type="number"
                      step="0.05"
                      min={0}
                      max={1}
                      value={settings.aiPipeline.verifierConfidenceMin}
                      onChange={(e) => updateAI("verifierConfidenceMin", parseFloat(e.target.value) || 0.7)}
                      className="mt-1 h-8 text-xs"
                    />
                  </div>
                </div>
              </div>

              <Separator />

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Max Concurrent Agents</label>
                  <Input
                    type="number"
                    value={settings.aiPipeline.maxConcurrentAgents}
                    onChange={(e) => updateAI("maxConcurrentAgents", parseInt(e.target.value) || 3)}
                    className="mt-1"
                    min={1}
                    max={10}
                  />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground">Drift Alert Threshold (PSI)</label>
                  <Input
                    type="number"
                    step="0.01"
                    value={settings.aiPipeline.driftAlertThreshold}
                    onChange={(e) => updateAI("driftAlertThreshold", parseFloat(e.target.value) || 0.1)}
                    className="mt-1"
                    min={0.01}
                    max={1}
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Pipeline Features</CardTitle>
            </CardHeader>
            <CardContent>
              <Toggle
                label="HMAC-SHA256 Evidence Chain"
                description="Enable cryptographic signing of all evidence batches"
                enabled={settings.aiPipeline.hmacEnabled}
                onChange={(v) => updateAI("hmacEnabled", v)}
              />
              <Separator />
              <Toggle
                label="Auto Investigation Creation"
                description="Automatically create investigations when triage classifies critical events"
                enabled={settings.aiPipeline.autoInvestigation}
                onChange={(v) => updateAI("autoInvestigation", v)}
              />
              <Separator />
              <Toggle
                label="XAI Explanations"
                description="Generate SHAP feature importance for every classification"
                enabled={settings.aiPipeline.xaiEnabled}
                onChange={(v) => updateAI("xaiEnabled", v)}
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
