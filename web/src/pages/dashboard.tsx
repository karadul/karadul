import { useEffect } from "react"
import {
  Activity,
  Network,
  Server,
  Users,
  ArrowUpRight,
  ArrowDownRight,
  Clock,
  RefreshCw,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Button } from "@/components/ui/button"
import { useStats, useNodes, usePeers } from "@/lib/api"
import { useKaradulStore } from "@/lib/store"
import { formatBytes, cn } from "@/lib/utils"
import { ErrorAlert } from "@/components/error-boundary"
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from "recharts"

export function DashboardPage() {
  const { data: stats, isLoading: statsLoading, error: statsError, refetch: refetchStats } = useStats()
  const { data: nodes, isLoading: nodesLoading, error: nodesError, refetch: refetchNodes } = useNodes()
  const { data: peers, isLoading: peersLoading, error: peersError, refetch: refetchPeers } = usePeers()
  const trafficHistory = useKaradulStore((state) => state.trafficHistory)
  const setIsLoading = useKaradulStore((state) => state.setIsLoading)

  useEffect(() => {
    setIsLoading(statsLoading || nodesLoading || peersLoading)
  }, [statsLoading, nodesLoading, peersLoading, setIsLoading])

  const isLoading = statsLoading || nodesLoading || peersLoading
  const error = statsError || nodesError || peersError

  const onlineNodes = nodes?.filter((n) => n.status === "online").length || 0
  const connectedPeers = peers?.filter((p) =>
    ["Direct", "Relayed"].includes(p.state)
  ).length || 0

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-muted-foreground">
            Overview of your Karadul mesh network
          </p>
        </div>
        <ErrorAlert
          title="Failed to load dashboard"
          message={error.message}
          onRetry={() => {
            refetchStats()
            refetchNodes()
            refetchPeers()
          }}
        />
      </div>
    )
  }

  const handleRefreshAll = () => {
    refetchStats()
    refetchNodes()
    refetchPeers()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-muted-foreground">
            Overview of your Karadul mesh network
          </p>
        </div>
        <Button
          variant="outline"
          size="icon"
          onClick={handleRefreshAll}
          disabled={isLoading}
        >
          <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="card-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Nodes</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-[60px]" />
            ) : (
              <>
                <div className="text-2xl font-bold">{nodes?.length || 0}</div>
                <p className="text-xs text-muted-foreground">
                  {onlineNodes} online
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="card-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Connected Peers</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-[60px]" />
            ) : (
              <>
                <div className="text-2xl font-bold">{connectedPeers}</div>
                <p className="text-xs text-muted-foreground">
                  of {peers?.length || 0} total
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="card-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Data Received</CardTitle>
            <ArrowDownRight className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-[60px]" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatBytes(stats?.totalRx || 0)}
                </div>
                <p className="text-xs text-muted-foreground">Total inbound</p>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="card-hover">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Data Sent</CardTitle>
            <ArrowUpRight className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-[60px]" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatBytes(stats?.totalTx || 0)}
                </div>
                <p className="text-xs text-muted-foreground">Total outbound</p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Network Traffic</CardTitle>
            <CardDescription>Data transfer over the last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-[200px] w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={trafficHistory}>
                  <defs>
                    <linearGradient id="colorRx" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorTx" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="time" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="rx"
                    stroke="#22c55e"
                    fillOpacity={1}
                    fill="url(#colorRx)"
                    name="Received"
                  />
                  <Area
                    type="monotone"
                    dataKey="tx"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorTx)"
                    name="Sent"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>Current system resource usage</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Skeleton className="h-4 w-[100px]" />
                    <Skeleton className="h-4 w-[50px]" />
                  </div>
                  <Skeleton className="h-2 w-full" />
                </div>
              ))
            ) : (
              <>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">CPU Usage</span>
                  </div>
                  <span className="text-sm font-medium">{stats?.cpuUsage?.toFixed(1) || 0}%</span>
                </div>
                <div className="h-2 rounded-full bg-muted">
                  <div
                    className="h-full rounded-full bg-primary transition-all"
                    style={{ width: `${Math.min(stats?.cpuUsage || 0, 100)}%` }}
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">Memory Usage</span>
                  </div>
                  <span className="text-sm font-medium">
                    {formatBytes(stats?.memoryUsage || 0)}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">Uptime</span>
                  </div>
                  <span className="text-sm font-medium">
                    {Math.floor((stats?.uptime || 0) / 3600)}h{" "}
                    {Math.floor(((stats?.uptime || 0) % 3600) / 60)}m
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">Goroutines</span>
                  </div>
                  <span className="text-sm font-medium">{stats?.goroutines || 0}</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
