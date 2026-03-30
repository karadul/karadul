import { useState, useEffect } from "react"
import {
  Settings,
  Key,
  Shield,
  Copy,
  Trash2,
  Plus,
  RefreshCw,
  Clock,
} from "lucide-react"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useAuthKeys, useCreateAuthKey, useDeleteAuthKey, useACL, useUpdateACL, useConfig, useUpdateConfig } from "@/lib/api"
import type { ACLRule, ServerConfig } from "@/lib/api"
import { formatDate, cn } from "@/lib/utils"
import { ErrorAlert } from "@/components/error-boundary"
import { EmptyState } from "@/components/empty-state"
import { toast } from "sonner"

function AuthKeySkeleton() {
  return (
    <TableRow>
      <TableCell><Skeleton className="h-4 w-32" /></TableCell>
      <TableCell><Skeleton className="h-4 w-20" /></TableCell>
      <TableCell><Skeleton className="h-4 w-16" /></TableCell>
      <TableCell><Skeleton className="h-4 w-20" /></TableCell>
      <TableCell><Skeleton className="h-8 w-8" /></TableCell>
    </TableRow>
  )
}

export function SettingsPage() {
  const { data: authKeys, isLoading, error, refetch } = useAuthKeys()
  const createAuthKey = useCreateAuthKey()
  const deleteAuthKey = useDeleteAuthKey()
  const { data: aclData, isLoading: aclLoading, error: aclError } = useACL()
  const updateACL = useUpdateACL()
  const { data: configData, isLoading: configLoading } = useConfig()
  const updateConfig = useUpdateConfig()
  const [newKeyExpiresIn, setNewKeyExpiresIn] = useState<string>("")
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [aclRules, setAclRules] = useState<ACLRule[]>([])
  const [configForm, setConfigForm] = useState<ServerConfig>({})

  // Sync config form from API data
  const configJson = JSON.stringify(configData)
  useEffect(() => {
    if (configData) {
      setConfigForm(configData)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [configJson])
  // Sync ACL rules from API data (only when rules actually change)
  const aclRulesJson = JSON.stringify(aclData?.rules)
  useEffect(() => {
    const rules = aclData?.rules
    if (rules) {
      setAclRules(rules)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aclRulesJson])

  const handleAddACLRule = () => {
    setAclRules((prev) => [
      ...prev,
      { action: "allow", src: ["*"], dst: ["*"] },
    ])
  }

  const updateACLRule = (index: number, field: keyof ACLRule, value: string | string[] | undefined) => {
    setAclRules((prev) =>
      prev.map((rule, i) => (i === index ? { ...rule, [field]: value } : rule)),
    )
  }

  const removeACLRule = (index: number) => {
    setAclRules((prev) => prev.filter((_, i) => i !== index))
  }

  const handleSaveACL = async () => {
    try {
      await updateACL.mutateAsync(aclRules)
      toast.success("ACL rules updated successfully")
    } catch (err) {
      toast.error(`Failed to update ACL: ${err instanceof Error ? err.message : "Unknown error"}`)
    }
  }

  const handleCreateKey = async () => {
    try {
      await createAuthKey.mutateAsync(newKeyExpiresIn || undefined)
      toast.success("Authentication key created successfully")
      setShowCreateDialog(false)
      setNewKeyExpiresIn("")
    } catch (err) {
      toast.error(`Failed to create key: ${err instanceof Error ? err.message : "Unknown error"}`)
    }
  }

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopiedKey(key)
    toast.success("Key copied to clipboard")
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleDeleteKey = async (id: string) => {
    try {
      await deleteAuthKey.mutateAsync(id)
      toast.success("Authentication key deleted successfully")
    } catch (err) {
      toast.error(`Failed to delete key: ${err instanceof Error ? err.message : "Unknown error"}`)
    }
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
          <p className="text-muted-foreground">
            Configure your Karadul mesh network
          </p>
        </div>
        <ErrorAlert
          title="Failed to load settings"
          message={error.message}
          onRetry={() => refetch()}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
          <p className="text-muted-foreground">
            Configure your Karadul mesh network
          </p>
        </div>
        <Button
          variant="outline"
          size="icon"
          onClick={() => refetch()}
          disabled={isLoading}
        >
          <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
        </Button>
      </div>

      <Tabs defaultValue="auth-keys" className="w-full">
        <TabsList>
          <TabsTrigger value="auth-keys">
            <Key className="h-4 w-4 mr-2" />
            Auth Keys
          </TabsTrigger>
          <TabsTrigger value="acl">
            <Shield className="h-4 w-4 mr-2" />
            ACL Rules
          </TabsTrigger>
          <TabsTrigger value="general">
            <Settings className="h-4 w-4 mr-2" />
            General
          </TabsTrigger>
        </TabsList>

        <TabsContent value="auth-keys" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Authentication Keys</CardTitle>
                <CardDescription>
                  Manage authentication keys for new nodes
                </CardDescription>
              </div>
              <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Key
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create Auth Key</DialogTitle>
                    <DialogDescription>
                      Create a new authentication key for node enrollment
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label>Expiration</Label>
                      <Select
                        value={newKeyExpiresIn}
                        onValueChange={setNewKeyExpiresIn}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Never expires" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="">Never expires</SelectItem>
                          <SelectItem value="1h">1 hour</SelectItem>
                          <SelectItem value="24h">24 hours</SelectItem>
                          <SelectItem value="7d">7 days</SelectItem>
                          <SelectItem value="30d">30 days</SelectItem>
                          <SelectItem value="90d">90 days</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <DialogFooter>
                    <Button
                      variant="outline"
                      onClick={() => setShowCreateDialog(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      onClick={handleCreateKey}
                      disabled={createAuthKey.isPending}
                    >
                      {createAuthKey.isPending ? (
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      ) : (
                        <Plus className="h-4 w-4 mr-2" />
                      )}
                      Create
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Key</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Used By</TableHead>
                      <TableHead className="w-[100px]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Array.from({ length: 3 }).map((_, i) => (
                      <AuthKeySkeleton key={i} />
                    ))}
                  </TableBody>
                </Table>
              ) : authKeys?.length === 0 ? (
                <EmptyState
                  icon={Key}
                  title="No auth keys"
                  description="Create an authentication key to allow new nodes to join your mesh network."
                  action={{
                    label: "Create Key",
                    onClick: () => setShowCreateDialog(true),
                  }}
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Key</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Used By</TableHead>
                      <TableHead className="w-[100px]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {authKeys?.map((authKey) => (
                      <TableRow key={authKey.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <code className="bg-muted px-2 py-1 rounded text-xs font-mono">
                              {authKey.key.slice(0, 20)}...
                            </code>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-6 w-6"
                              onClick={() => handleCopyKey(authKey.key)}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                            {copiedKey === authKey.key && (
                              <Badge variant="outline" className="text-xs">
                                Copied!
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>{formatDate(authKey.createdAt)}</TableCell>
                        <TableCell>
                          {authKey.expiresAt ? (
                            <div className="flex items-center gap-1 text-amber-600">
                              <Clock className="h-3 w-3" />
                              {formatDate(authKey.expiresAt)}
                            </div>
                          ) : (
                            <Badge variant="outline">Never</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {authKey.used ? (
                            <Badge variant="outline">Used</Badge>
                          ) : (
                            <span className="text-muted-foreground">
                              Unused
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleDeleteKey(authKey.id)}
                            disabled={deleteAuthKey.isPending}
                          >
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="acl" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Access Control Rules</CardTitle>
                <CardDescription>
                  Configure network access control rules
                </CardDescription>
              </div>
              <Button onClick={() => handleAddACLRule()} size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Add Rule
              </Button>
            </CardHeader>
            <CardContent>
              {aclError ? (
                <ErrorAlert
                  title="Failed to load ACL rules"
                  message={aclError.message}
                  onRetry={() => refetch()}
                />
              ) : aclLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="flex items-center gap-4">
                      <Skeleton className="h-10 w-24" />
                      <Skeleton className="h-10 flex-1" />
                      <Skeleton className="h-10 flex-1" />
                      <Skeleton className="h-10 w-24" />
                      <Skeleton className="h-10 w-10" />
                    </div>
                  ))}
                </div>
              ) : aclRules.length === 0 ? (
                <EmptyState
                  icon={Shield}
                  title="No ACL rules"
                  description="Add access control rules to restrict network traffic between nodes."
                  action={{
                    label: "Add Rule",
                    onClick: handleAddACLRule,
                  }}
                />
              ) : (
                <div className="space-y-3">
                  {aclRules.map((rule, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-4 p-3 rounded-lg border bg-card"
                    >
                      <Select
                        value={rule.action}
                        onValueChange={(value) =>
                          updateACLRule(index, "action", value)
                        }
                      >
                        <SelectTrigger className="w-28">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="allow">Allow</SelectItem>
                          <SelectItem value="deny">Deny</SelectItem>
                        </SelectContent>
                      </Select>

                      <div className="flex-1">
                        <Label className="text-xs text-muted-foreground">Source</Label>
                        <Input
                          value={rule.src.join(", ")}
                          onChange={(e) =>
                            updateACLRule(
                              index,
                              "src",
                              e.target.value.split(",").map((s) => s.trim()).filter(Boolean),
                            )
                          }
                          placeholder="100.64.0.0/10, *"
                          className="mt-1"
                        />
                      </div>

                      <div className="flex-1">
                        <Label className="text-xs text-muted-foreground">Destination</Label>
                        <Input
                          value={rule.dst.join(", ")}
                          onChange={(e) =>
                            updateACLRule(
                              index,
                              "dst",
                              e.target.value.split(",").map((s) => s.trim()).filter(Boolean),
                            )
                          }
                          placeholder="100.64.0.0/10, *"
                          className="mt-1"
                        />
                      </div>

                      <div className="w-28">
                        <Label className="text-xs text-muted-foreground">Ports</Label>
                        <Input
                          value={rule.ports?.join(", ") || ""}
                          onChange={(e) =>
                            updateACLRule(
                              index,
                              "ports",
                              e.target.value
                                ? e.target.value.split(",").map((s) => s.trim()).filter(Boolean)
                                : undefined,
                            )
                          }
                          placeholder="*, 80, 443"
                          className="mt-1"
                        />
                      </div>

                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeACLRule(index)}
                        className="mt-5"
                      >
                        <Trash2 className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
            {aclRules.length > 0 && (
              <div className="px-6 pb-6 flex justify-end">
                <Button
                  onClick={handleSaveACL}
                  disabled={updateACL.isPending}
                >
                  {updateACL.isPending ? "Saving..." : "Save Rules"}
                </Button>
              </div>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="general" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
              <CardDescription>
                Configure general network settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {configLoading ? (
                <div className="space-y-3">
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              ) : (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="listen-addr">Listen Address</Label>
                    <Input
                      id="listen-addr"
                      value={configForm.addr || ""}
                      onChange={(e) =>
                        setConfigForm((prev) => ({ ...prev, addr: e.target.value }))
                      }
                      placeholder=":8080"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="subnet">CGNAT Subnet</Label>
                    <Input
                      id="subnet"
                      value={configForm.subnet || ""}
                      onChange={(e) =>
                        setConfigForm((prev) => ({ ...prev, subnet: e.target.value }))
                      }
                      placeholder="100.64.0.0/10"
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="approval-mode">Approval Mode</Label>
                    <Select
                      value={configForm.approval_mode || "auto"}
                      onValueChange={(value) =>
                        setConfigForm((prev) => ({ ...prev, approval_mode: value }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">Auto-approve</SelectItem>
                        <SelectItem value="manual">Manual approval</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="log-level">Log Level</Label>
                    <Select
                      value={configForm.log_level || "info"}
                      onValueChange={(value) =>
                        setConfigForm((prev) => ({ ...prev, log_level: value }))
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="debug">Debug</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                        <SelectItem value="warn">Warn</SelectItem>
                        <SelectItem value="error">Error</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="rate-limit">Rate Limit (req/s, 0=disabled)</Label>
                    <Input
                      id="rate-limit"
                      type="number"
                      value={configForm.rate_limit ?? 100}
                      onChange={(e) =>
                        setConfigForm((prev) => ({
                          ...prev,
                          rate_limit: parseInt(e.target.value, 10) || 0,
                        }))
                      }
                      placeholder="100"
                    />
                  </div>
                  <Button
                    onClick={() => updateConfig.mutate(configForm)}
                    disabled={updateConfig.isPending}
                  >
                    {updateConfig.isPending ? "Saving..." : "Save Changes"}
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
