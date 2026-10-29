import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar } from './components/Sidebar';
import { Header } from './components/Header';
import { DemoGuideModal } from './components/DemoGuideModal';
import { OverviewPage } from './pages/OverviewPage';
import { AttackLabPage } from './pages/AttackLabPage';
import { LiveMonitoringPage } from './pages/LiveMonitoringPage';
import { ThreatDetectionPage } from './pages/ThreatDetectionPage';
import { PreventionPage } from './pages/PreventionPage';
import { MachineLearningPage } from './pages/MachineLearningPage';
import { EventDetailPage } from './pages/EventDetailPage';
import {
  fetchEvents,
  fetchEventStatistics,
  fetchMonitoringStatus,
  fetchNetworkStatistics,
  fetchPreventionStatus,
  fetchBlockedIPs,
  fetchMLMetrics,
  fetchSimulationStatus,
  startMonitoring,
  stopMonitoring,
  setPreventionMode,
  blockIP,
  unblockIP,
  startAttackSimulation,
  stopAttackSimulation
} from './services/api';
import { useCyberShieldWebSocket, WebSocketMessage } from './services/websocket';
import {
  SecurityEvent,
  EventStatistics,
  MonitoringStatus,
  NetworkStatistics,
  PreventionStatus,
  BlockedAddress,
  MLMetrics,
  AttackSimulationStatus,
  PreventionMode
} from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [isGuideOpen, setIsGuideOpen] = useState<boolean>(false);

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<EventStatistics | null>(null);
  const [netStats, setNetStats] = useState<NetworkStatistics | null>(null);
  const [monitoringStatus, setMonitoringStatus] = useState<MonitoringStatus | null>(null);
  const [preventionStatus, setPreventionStatus] = useState<PreventionStatus | null>(null);
  const [blockedIPs, setBlockedIPs] = useState<BlockedAddress[]>([]);
  const [mlMetrics, setMlMetrics] = useState<MLMetrics | null>(null);
  const [simStatus, setSimStatus] = useState<AttackSimulationStatus | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [evs, st, mon, net, prev, blk, ml, sim] = await Promise.all([
        fetchEvents({ limit: 50 }),
        fetchEventStatistics(),
        fetchMonitoringStatus(),
        fetchNetworkStatistics(),
        fetchPreventionStatus(),
        fetchBlockedIPs(),
        fetchMLMetrics(),
        fetchSimulationStatus()
      ]);
      setEvents(evs);
      setStats(st);
      setMonitoringStatus(mon);
      setNetStats(net);
      setPreventionStatus(prev);
      setBlockedIPs(blk);
      setMlMetrics(ml);
      setSimStatus(sim);
    } catch (e) {
      console.debug('Failed to load initial CyberShield telemetry', e);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, [loadData]);

  // WebSocket message handler
  const handleWsMessage = useCallback((msg: WebSocketMessage) => {
    if (msg.type === 'NEW_SECURITY_EVENT') {
      const newEv = msg.data as SecurityEvent;
      setEvents(prev => [newEv, ...prev]);
      fetchEventStatistics().then(setStats);
      fetchBlockedIPs().then(setBlockedIPs);
      fetchPreventionStatus().then(setPreventionStatus);
    } else if (msg.type === 'TRAFFIC_STATS_UPDATE') {
      setNetStats(msg.data);
    } else if (msg.type === 'MONITORING_STATUS_CHANGED') {
      setMonitoringStatus(msg.data);
    } else if (msg.type === 'ATTACK_SIMULATION_UPDATE') {
      setSimStatus(msg.data);
    } else if (msg.type === 'PREVENTION_STATUS_CHANGED') {
      fetchPreventionStatus().then(setPreventionStatus);
      fetchBlockedIPs().then(setBlockedIPs);
    } else if (msg.type === 'PCAP_REPLAY_COMPLETED') {
      loadData();
    }
  }, [loadData]);

  const { isConnected } = useCyberShieldWebSocket(handleWsMessage);

  const handleToggleMonitoring = async () => {
    if (monitoringStatus?.is_running) {
      await stopMonitoring();
    } else {
      await startMonitoring({});
    }
    const mon = await fetchMonitoringStatus();
    setMonitoringStatus(mon);
  };

  const handleStartCapture = async (iface?: string) => {
    await startMonitoring({ interface: iface });
    const mon = await fetchMonitoringStatus();
    setMonitoringStatus(mon);
  };

  const handleStartPcap = async (path: string) => {
    await startMonitoring({ pcap_path: path });
    const mon = await fetchMonitoringStatus();
    setMonitoringStatus(mon);
  };

  const handleStopCapture = async () => {
    await stopMonitoring();
    const mon = await fetchMonitoringStatus();
    setMonitoringStatus(mon);
  };

  const handleModeChange = async (mode: PreventionMode) => {
    await setPreventionMode(mode);
    const prev = await fetchPreventionStatus();
    setPreventionStatus(prev);
  };

  const handleBlockIP = async (ip: string, reason: string, duration: number) => {
    await blockIP(ip, reason, duration);
    const blk = await fetchBlockedIPs();
    const prev = await fetchPreventionStatus();
    setBlockedIPs(blk);
    setPreventionStatus(prev);
  };

  const handleUnblockIP = async (ip: string) => {
    await unblockIP(ip);
    const blk = await fetchBlockedIPs();
    const prev = await fetchPreventionStatus();
    setBlockedIPs(blk);
    setPreventionStatus(prev);
  };

  const handleStartAttack = async (attackType: string, autoEnforce: boolean) => {
    const res = await startAttackSimulation({
      attack_type: attackType,
      auto_enforce: autoEnforce
    });
    setSimStatus(res);
    if (autoEnforce) {
      const prev = await fetchPreventionStatus();
      setPreventionStatus(prev);
    }
  };

  const handleStopAttack = async () => {
    await stopAttackSimulation();
    const sim = await fetchSimulationStatus();
    setSimStatus(sim);
  };

  const handleSelectEvent = (event: SecurityEvent) => {
    setSelectedEvent(event);
    setActiveTab('event-detail');
  };

  return (
    <div className="app-container">
      <Sidebar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'event-detail') setSelectedEvent(null);
        }}
        threatCount={stats?.total_events ?? 0}
        blockedCount={preventionStatus?.active_blocks_count ?? 0}
      />

      <div className="main-content">
        <Header
          isWsConnected={isConnected}
          monitoringMode={monitoringStatus?.mode ?? 'IDLE'}
          isMonitoring={monitoringStatus?.is_running ?? false}
          preventionMode={preventionStatus?.mode ?? 'OBSERVE'}
          onToggleMonitoring={handleToggleMonitoring}
          onRefresh={loadData}
          onOpenGuide={() => setIsGuideOpen(true)}
          onNavigateTab={setActiveTab}
        />

        <main className="content-body">
          {activeTab === 'overview' && (
            <OverviewPage
              stats={stats}
              netStats={netStats}
              prevStatus={preventionStatus}
              events={events}
              onSelectEvent={handleSelectEvent}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'attack-lab' && (
            <AttackLabPage
              simStatus={simStatus}
              preventionMode={preventionStatus?.mode ?? 'OBSERVE'}
              onStartAttack={handleStartAttack}
              onStopAttack={handleStopAttack}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'live' && (
            <LiveMonitoringPage
              status={monitoringStatus}
              netStats={netStats}
              onStartCapture={handleStartCapture}
              onStartPcap={handleStartPcap}
              onStopCapture={handleStopCapture}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'threats' && (
            <ThreatDetectionPage
              events={events}
              onSelectEvent={handleSelectEvent}
              onRefresh={loadData}
            />
          )}

          {activeTab === 'prevention' && (
            <PreventionPage
              status={preventionStatus}
              blockedIPs={blockedIPs}
              onModeChange={handleModeChange}
              onBlockIP={handleBlockIP}
              onUnblockIP={handleUnblockIP}
              onRefresh={loadData}
            />
          )}

          {activeTab === 'ml' && (
            <MachineLearningPage
              metrics={mlMetrics}
            />
          )}

          {activeTab === 'event-detail' && (
            <EventDetailPage
              event={selectedEvent}
              onBack={() => setActiveTab('threats')}
            />
          )}
        </main>
      </div>

      {/* Professor Presentation Walkthrough Modal */}
      <DemoGuideModal
        isOpen={isGuideOpen}
        onClose={() => setIsGuideOpen(false)}
        onNavigateTab={setActiveTab}
        onStartAttack={handleStartAttack}
      />
    </div>
  );
};

export default App;
