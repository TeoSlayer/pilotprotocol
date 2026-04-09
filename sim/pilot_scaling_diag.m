%% pilot_scaling_diag.m — Detailed Diagnostic Output for Scaling Analysis
% Companion to pilot_scaling_sim.m — prints comprehensive intermediate
% values, identifies model issues, and produces detailed text analysis.
%
% Run in MATLAB Online: upload and click Run. All output is text (fprintf).

clear; clc; close all;

%% =====================================================================
%% 1. PROFILED CONSTANTS
%% =====================================================================

% --- Registry Server ---
ed25519Verify_us       = 28;         % ~28us per Ed25519 verify
handleRegister_us      = 50;         % 50us under write lock
handleHeartbeat_us     = 0;          % Phase 0: atomic, no lock
resolveRLock_us        = 2;          % RLock hold time for resolve
jsonEncode_us          = 5;          % JSON encode/decode per msg
binaryEncode_us        = 0.5;        % Binary wire encode/decode
keepalive_s            = 30;         % daemon heartbeat interval
keepalive_p3_s         = 60;         % Phase 3: 60s interval
staleThreshold_s       = 180;        % 3 min stale → reap
reapInterval_s         = 10;         % Phase 1: 10s reap ticker
reapChunkSize          = 10000;      % Phase 1: nodes per reap tick
saveTicker_s           = 1;          % current save coalescing
saveTicker_wal_s       = 60;         % Phase 2: WAL compaction
numShards              = 256;        % Phase 2: sharded locks
heartbeatVerifySkipN   = 5;          % Phase 3: verify every Nth

% --- Transport ---
MSS                    = 4096;       % bytes
initialCwnd_bytes      = 40960;      % 10 segments
maxCwnd_bytes          = 1024*1024;  % 1MB
initialSsthresh_bytes  = 512*1024;   % 512KB
delayedAck_ms          = 40;
pktHeader_bytes        = 34;
pktHeaderEncrypted     = 70;

% --- Wire format sizes ---
jsonHeartbeat_bytes    = 150;        % JSON heartbeat request
jsonHBResp_bytes       = 50;         % JSON heartbeat response

% --- Network RTTs ---
rtt_tcp_ms             = 20;         % registry RTT (regional)
rtt_beacon_ms          = 20;         % beacon co-located
rtt_tunnel_ms          = 30;         % peer-to-peer UDP

% --- Infrastructure ---
cores_p1 = 8;   % c2-standard-8
cores_p2 = 16;  % c2-standard-16
cores_p3 = 30;  % c2-standard-30

% --- Traffic assumptions ---
churn_rate_per_min     = 0.001;      % 0.1% churn/min (steady state)
resolve_freq_per_node  = 5/300;      % 5 peers per 5 minutes
peers_per_node         = 5;

fprintf('========================================\n');
fprintf('  PILOT PROTOCOL SCALING DIAGNOSTICS\n');
fprintf('========================================\n\n');

%% =====================================================================
%% 2. BASELINE LATENCY BREAKDOWN (no contention)
%% =====================================================================

fprintf('--- 2. BASELINE LATENCY (zero contention) ---\n\n');

% Register: fixed costs (no lock wait)
reg_tcp_connect    = rtt_tcp_ms;
reg_json_encode    = jsonEncode_us / 1000;  % ms
reg_handler        = handleRegister_us / 1000;
reg_json_response  = jsonEncode_us / 1000;
reg_tcp_response   = rtt_tcp_ms;
reg_stun           = rtt_beacon_ms;
reg_beacon         = rtt_beacon_ms;
reg_total_baseline = reg_tcp_connect + reg_json_encode + reg_handler + ...
                     reg_json_response + reg_tcp_response + reg_stun + reg_beacon;

fprintf('Register Operation (baseline, no lock wait):\n');
fprintf('  TCP connect (SYN+SYN-ACK):      %8.3f ms\n', reg_tcp_connect);
fprintf('  JSON encode request:             %8.3f ms\n', reg_json_encode);
fprintf('  handleRegister (under lock):     %8.3f ms\n', reg_handler);
fprintf('  JSON encode response:            %8.3f ms\n', reg_json_response);
fprintf('  TCP response:                    %8.3f ms\n', reg_tcp_response);
fprintf('  STUN discover:                   %8.3f ms\n', reg_stun);
fprintf('  Beacon register:                 %8.3f ms\n', reg_beacon);
fprintf('  TOTAL baseline:                  %8.3f ms\n', reg_total_baseline);
fprintf('  Network-bound portion:           %8.1f%%\n', ...
    (reg_tcp_connect + reg_tcp_response + reg_stun + reg_beacon) / reg_total_baseline * 100);
fprintf('\n');

% Message: fixed costs
msg_resolve        = 2 * rtt_tcp_ms + ed25519Verify_us/1000;
msg_conn_setup     = 1.5 * rtt_tunnel_ms;
msg_data_1kb       = rtt_tunnel_ms;
msg_dack           = delayedAck_ms;
msg_fin            = rtt_tunnel_ms;
msg_total_baseline = msg_resolve + msg_conn_setup + msg_data_1kb + msg_dack + msg_fin;

fprintf('Send 1KB Message (baseline, uncached resolve):\n');
fprintf('  Resolve (2xRTT + verify):        %8.3f ms\n', msg_resolve);
fprintf('  Connection setup (1.5xRTT):      %8.3f ms\n', msg_conn_setup);
fprintf('  Data transfer (1 segment):       %8.3f ms\n', msg_data_1kb);
fprintf('  Delayed ACK:                     %8.3f ms\n', msg_dack);
fprintf('  FIN exchange:                    %8.3f ms\n', msg_fin);
fprintf('  TOTAL baseline:                  %8.3f ms\n', msg_total_baseline);
fprintf('\n');

% Message with cached resolve (Phase 2+)
msg_cached = msg_conn_setup + msg_data_1kb + msg_dack + msg_fin;
fprintf('Send 1KB Message (cached resolve):\n');
fprintf('  TOTAL (skip resolve):            %8.3f ms\n', msg_cached);
fprintf('  Savings from cache:              %8.3f ms (%.0f%%)\n', ...
    msg_resolve, msg_resolve / msg_total_baseline * 100);
fprintf('\n');

% File transfer
fprintf('File Transfer Times (AIMD model, 30ms RTT):\n');
rtt_s = rtt_tunnel_ms / 1000;
file_sizes = [1024, 100*1024, 1e6, 10e6, 100e6];
file_labels = {'1 KB', '100 KB', '1 MB', '10 MB', '100 MB'};
for fi = 1:length(file_sizes)
    ft = file_transfer_time(file_sizes(fi), rtt_s, MSS, initialCwnd_bytes, initialSsthresh_bytes);
    fprintf('  %-8s  bulk transfer: %10.1f ms  (%.1f segments, %.2f MB/s effective)\n', ...
        file_labels{fi}, ft*1000, ceil(file_sizes(fi)/MSS), file_sizes(fi)/ft/1e6);
end
fprintf('\n');

%% =====================================================================
%% 3. LOCK CONTENTION ANALYSIS — STEADY STATE
%% =====================================================================

fprintf('--- 3. LOCK CONTENTION (Steady State) ---\n\n');

N_points = [1000, 5000, 12700, 50000, 100000, 300000, 500000, 1000000];
N_labels = {'1K', '5K', '12.7K', '50K', '100K', '300K', '500K', '1M'};

fprintf('%-8s | %12s | %12s | %12s | %12s | %12s | %12s\n', ...
    'Nodes', 'Reg/sec', 'Reap cost/s', 'Write rate', 'Util(single)', 'Wait(single)', 'Wait(shard)');
fprintf('%s\n', repmat('-', 1, 90));

for ni = 1:length(N_points)
    N = N_points(ni);

    % Steady-state registration rate (churn)
    reg_rate = N * churn_rate_per_min / 60;

    % Reap: amortized cost = (N / reapChunkSize * 1us_per_node * chunkSize) / reapInterval
    %   = N * 1us / reapInterval  (simplified)
    reap_cost_s = N * 1e-6 / reapInterval_s;  % seconds of lock per second

    % Total write lock demand (rate × service time gives utilization directly)
    write_rate = reg_rate;  % reap cost is separate (bulk hold)
    write_lock_service = handleRegister_us * 1e-6;

    % M/M/1 utilization
    rho_single = write_rate * write_lock_service;

    % M/M/1 mean wait
    if rho_single < 1
        wait_single = write_lock_service / (1 - rho_single);
    else
        wait_single = Inf;
    end

    % Sharded: global lock only for nextNode (5us)
    shard_service = 5e-6;
    rho_shard = write_rate * shard_service;
    if rho_shard < 1
        wait_shard = shard_service / (1 - rho_shard);
    else
        wait_shard = Inf;
    end

    fprintf('%-8s | %10.1f/s | %10.3f ms | %10.1f/s | %10.4f%%  | %10.3f us | %10.3f us\n', ...
        N_labels{ni}, reg_rate, reap_cost_s*1000, write_rate, ...
        rho_single*100, wait_single*1e6, wait_shard*1e6);
end
fprintf('\n');
fprintf('KEY INSIGHT: Steady-state churn is so low (0.1%%/min) that lock\n');
fprintf('contention never becomes a bottleneck. At 1M nodes, only ~16.7\n');
fprintf('registrations/sec, holding the lock for 0.83ms/sec total.\n');
fprintf('The REAL bottleneck is BURST scenarios (storms).\n\n');

%% =====================================================================
%% 4. STORM SCENARIOS — WHERE PHASES ACTUALLY MATTER
%% =====================================================================

fprintf('--- 4. STORM ANALYSIS ---\n\n');

% === Storm A: Registry Restart ===
fprintf('=== Storm A: Registry Restart (all nodes re-register) ===\n\n');

restart_agents = [100000, 300000, 1000000];
restart_labels = {'100K', '300K', '1M'};

for ri = 1:length(restart_agents)
    N = restart_agents(ri);
    fprintf('--- %s agents ---\n', restart_labels{ri});

    % Without mitigation: all agents re-register over ~60s (heartbeat timeout detection)
    unreg_rate = N / 60;  % all in 60 seconds

    % With Phase 1 mitigation (accept throttle + jitter + backoff)
    %   First 60s: 1000/sec accept throttle
    %   Remaining: spread over next 60-120s with backoff
    throttled_first60 = min(N, 60000);  % 1000/sec × 60s
    remaining = N - throttled_first60;
    throttled_rate_phase2 = remaining / 120;  % spread with backoff

    % Lock analysis: unmitigated
    rho_unreg = unreg_rate * handleRegister_us * 1e-6;
    if rho_unreg < 1
        wait_unreg = handleRegister_us * 1e-6 / (1 - rho_unreg) * 1e6;
    else
        wait_unreg = Inf;
    end

    % Lock analysis: mitigated peak (throttle phase)
    rho_throttle = 1000 * handleRegister_us * 1e-6;
    wait_throttle = handleRegister_us * 1e-6 / (1 - rho_throttle) * 1e6;

    % Lock analysis: mitigated phase 2 (post-throttle)
    rho_post = throttled_rate_phase2 * handleRegister_us * 1e-6;
    if rho_post < 1
        wait_post = handleRegister_us * 1e-6 / (1 - rho_post) * 1e6;
    else
        wait_post = Inf;
    end

    % Sharded lock analysis (Phase 2+): 5us global portion
    rho_shard_unreg = unreg_rate * 5e-6;
    if rho_shard_unreg < 1
        wait_shard_unreg = 5e-6 / (1 - rho_shard_unreg) * 1e6;
    else
        wait_shard_unreg = Inf;
    end

    fprintf('  Unmitigated:\n');
    fprintf('    Peak reg rate:           %12.0f/sec\n', unreg_rate);
    fprintf('    Write lock utilization:  %12.2f%%\n', min(rho_unreg, 1)*100);
    fprintf('    Mean lock wait:          %12.1f us%s\n', min(wait_unreg, 999999), ...
        ternary(rho_unreg >= 1, ' [SATURATED]', ''));
    fprintf('    Recovery time:                 60 sec\n');

    fprintf('  Phase 1 (throttle+jitter+backoff):\n');
    fprintf('    Throttle phase (0-60s):  %12.0f/sec (capped)\n', 1000);
    fprintf('    Lock util (throttle):    %12.2f%%\n', rho_throttle*100);
    fprintf('    Lock wait (throttle):    %12.1f us\n', wait_throttle);
    fprintf('    Post-throttle rate:      %12.0f/sec\n', throttled_rate_phase2);
    fprintf('    Lock util (post):        %12.2f%%\n', min(rho_post, 1)*100);
    fprintf('    Lock wait (post):        %12.1f us%s\n', min(wait_post, 999999), ...
        ternary(rho_post >= 1, ' [SATURATED]', ''));
    fprintf('    Recovery time:              ~180 sec\n');

    fprintf('  Phase 2 (sharded, unmitigated):\n');
    fprintf('    Global lock portion:           5 us\n');
    fprintf('    Lock util (global):      %12.2f%%\n', min(rho_shard_unreg, 1)*100);
    fprintf('    Lock wait (global):      %12.1f us%s\n', min(wait_shard_unreg, 999999), ...
        ternary(rho_shard_unreg >= 1, ' [SATURATED]', ''));

    % CPU for Ed25519 verify during re-registration
    cpu_verify = unreg_rate * ed25519Verify_us * 1e-6;  % cores
    fprintf('  CPU impact:\n');
    fprintf('    Ed25519 verify:          %12.1f cores (unmitigated)\n', cpu_verify);
    fprintf('    Ed25519 verify:          %12.1f cores (throttled)\n', 1000 * ed25519Verify_us * 1e-6);

    % Memory
    mem_gb = N * (2048 + 8192 + 300) / 1e9;
    fprintf('  Memory at full re-reg:     %12.1f GB\n', mem_gb);
    fprintf('\n');
end

% === Storm B: Cron Burst ===
fprintf('=== Storm B: Cron Burst (agents resolve peers simultaneously) ===\n\n');

cron_configs = [50000, 200000, 500000];
cron_labels  = {'50K', '200K', '500K'};
jitter_s     = 30;

for ci = 1:length(cron_configs)
    agents = cron_configs(ci);
    fprintf('--- %s agents, %d peers each, %ds jitter ---\n', cron_labels{ci}, peers_per_node, jitter_s);

    total_resolves = agents * peers_per_node;
    peak_resolve_rate = total_resolves / jitter_s;

    % CPU for Ed25519 verify
    cpu_verify = peak_resolve_rate * ed25519Verify_us * 1e-6;

    % RLock contention (single lock, Phase 1)
    rlock_service_p1 = (resolveRLock_us + ed25519Verify_us) * 1e-6;  % 30us total
    rho_rlock_p1 = peak_resolve_rate * rlock_service_p1;

    % RLock contention (sharded, Phase 2)
    rlock_service_p2 = (resolveRLock_us / numShards + ed25519Verify_us) * 1e-6;
    rho_rlock_p2 = peak_resolve_rate * rlock_service_p2;  % NOTE: verify is NOT sharded, it's CPU bound

    % Phase 3: binary + verify skip (only 1/5 verifies)
    effective_verify_p3 = ed25519Verify_us / heartbeatVerifySkipN;
    rlock_service_p3 = (binaryEncode_us + resolveRLock_us / numShards) * 1e-6;
    cpu_verify_p3 = peak_resolve_rate * effective_verify_p3 * 1e-6;

    fprintf('  Total resolves:            %12.0f\n', total_resolves);
    fprintf('  Peak resolve rate:         %12.0f/sec\n', peak_resolve_rate);
    fprintf('  Bandwidth (in+out):        %10.1f MB/s (350B/resolve)\n', peak_resolve_rate * 350 / 1e6);
    fprintf('\n');

    fprintf('  Phase 1 (single RLock, 8 cores):\n');
    fprintf('    RLock service time:      %12.1f us\n', rlock_service_p1 * 1e6);
    fprintf('    RLock utilization:       %12.1f%%\n', min(rho_rlock_p1, 1) * 100);
    fprintf('    CPU for verify:          %12.1f cores (of %d)\n', cpu_verify, cores_p1);
    fprintf('    CPU headroom:            %12.1f%%\n', max(0, (1 - cpu_verify/cores_p1)*100));
    if cpu_verify > cores_p1
        fprintf('    *** CPU SATURATED ***\n');
    end

    fprintf('  Phase 2 (sharded, 16 cores):\n');
    fprintf('    Shard lock service:      %12.4f us (lock) + 28 us (verify, no lock)\n', resolveRLock_us / numShards);
    fprintf('    CPU for verify:          %12.1f cores (of %d)\n', cpu_verify, cores_p2);
    fprintf('    Lock contention:         ELIMINATED (sharded)\n');
    fprintf('    CPU headroom:            %12.1f%%\n', max(0, (1 - cpu_verify/cores_p2)*100));

    fprintf('  Phase 3 (sharded + binary + skip verify, 30 cores):\n');
    fprintf('    CPU for verify (1/%d):   %12.1f cores (of %d)\n', ...
        heartbeatVerifySkipN, cpu_verify_p3, cores_p3);

    % With daemon resolve cache (Phase 2+)
    cache_hit_rate = 0.8;  % assume 80% peers already cached
    effective_rate = peak_resolve_rate * (1 - cache_hit_rate);
    cpu_cached = effective_rate * ed25519Verify_us * 1e-6;
    fprintf('  With resolve cache (%.0f%% hit):\n', cache_hit_rate*100);
    fprintf('    Effective resolve rate:  %12.0f/sec (%.0fx reduction)\n', ...
        effective_rate, 1/(1-cache_hit_rate));
    fprintf('    CPU for verify:          %12.1f cores\n', cpu_cached);
    fprintf('\n');
end

% === Storm C: Mass deployment ===
fprintf('=== Storm C: Mass Deployment (new agents joining) ===\n\n');

deploy_counts = [1000, 10000, 50000];
deploy_labels = {'1K', '10K', '50K'};
deploy_window = 30;  % seconds

for di = 1:length(deploy_counts)
    agents = deploy_counts(di);
    fprintf('--- %s new agents over %ds ---\n', deploy_labels{di}, deploy_window);

    reg_rate = agents / deploy_window;

    % Each new agent: register + setVisibility + setHostname + beacon register
    % = 4 ops, register under write lock, others under RLock or no lock
    total_ops_rate = reg_rate * 4;

    rho_single = reg_rate * handleRegister_us * 1e-6;
    rho_shard = reg_rate * 5e-6;

    fprintf('  Registration rate:         %12.0f/sec\n', reg_rate);
    fprintf('  Total ops rate:            %12.0f/sec\n', total_ops_rate);
    fprintf('  Write lock util (single):  %12.2f%%\n', rho_single * 100);
    fprintf('  Write lock util (shard):   %12.4f%%\n', rho_shard * 100);
    fprintf('  CPU (verify):              %12.2f cores\n', reg_rate * ed25519Verify_us * 1e-6);
    fprintf('\n');
end

%% =====================================================================
%% 5. THROUGHPUT CEILINGS
%% =====================================================================

fprintf('--- 5. THROUGHPUT CEILINGS ---\n\n');

fprintf('%-25s | %12s | %12s | %12s\n', 'Operation', 'Phase 1', 'Phase 2', 'Phase 3');
fprintf('%s\n', repmat('-', 1, 70));

% Heartbeat: limited by sig verify CPU
max_hb_p1 = cores_p1 / (ed25519Verify_us * 1e-6);
max_hb_p2 = cores_p2 / (ed25519Verify_us * 1e-6);
max_hb_p3 = cores_p3 / (ed25519Verify_us / heartbeatVerifySkipN * 1e-6);

fprintf('%-25s | %10.0fK/s | %10.0fK/s | %10.0fK/s\n', 'Max Heartbeat (CPU)', ...
    max_hb_p1/1e3, max_hb_p2/1e3, max_hb_p3/1e3);

% How many nodes each can support (heartbeat rate = N / interval)
max_nodes_hb_p1 = max_hb_p1 * keepalive_s;
max_nodes_hb_p2 = max_hb_p2 * keepalive_s;
max_nodes_hb_p3 = max_hb_p3 * keepalive_p3_s;

fprintf('%-25s | %10.0fK   | %10.0fK   | %10.0fK  \n', '  -> Max nodes (HB CPU)', ...
    max_nodes_hb_p1/1e3, max_nodes_hb_p2/1e3, max_nodes_hb_p3/1e3);

% Resolve: limited by Ed25519 verify CPU (NOT by locks after Phase 2)
max_resolve_p1 = cores_p1 / (ed25519Verify_us * 1e-6);
max_resolve_p2 = cores_p2 / (ed25519Verify_us * 1e-6);  % SAME formula (CPU bound, not lock bound)
max_resolve_p3 = cores_p3 / (ed25519Verify_us / heartbeatVerifySkipN * 1e-6);

fprintf('%-25s | %10.0fK/s | %10.0fK/s | %10.0fK/s\n', 'Max Resolve (CPU)', ...
    max_resolve_p1/1e3, max_resolve_p2/1e3, max_resolve_p3/1e3);

% Registration: limited by global write lock
max_reg_single = 1 / (handleRegister_us * 1e-6);
max_reg_shard  = 1 / (5e-6);  % Phase 2: 5us global portion

fprintf('%-25s | %10.0fK/s | %10.0fK/s | %10.0fK/s\n', 'Max Registration (lock)', ...
    max_reg_single/1e3, max_reg_shard/1e3, max_reg_shard/1e3);

% Snapshot save cost
fprintf('\n');
fprintf('Snapshot (flushSave) cost per N:\n');
for ni = 1:length(N_points)
    N = N_points(ni);
    % Current: marshal under lock ~5us per node (base64 + time.Format + json)
    save_time_current = N * 5e-6;
    % Phase 1: copy under lock ~0.5us per node, marshal outside
    save_time_p1 = N * 0.5e-6;  % just pointer copies
    % Phase 2: WAL + 60s compaction (save still locks but 60x less frequent)
    save_time_p2 = save_time_p1;  % same lock time, but every 60s instead of 1s
    fprintf('  %-8s: current=%.1fms (every 1s)  Phase1=%.1fms (every 1s)  Phase2=%.1fms (every 60s)\n', ...
        N_labels{ni}, save_time_current*1000, save_time_p1*1000, save_time_p2*1000);
end

%% =====================================================================
%% 6. PERSISTENCE ANALYSIS
%% =====================================================================

fprintf('\n--- 6. PERSISTENCE OVERHEAD ---\n\n');

for ni = 1:length(N_points)
    N = N_points(ni);
    % Snapshot size (~500B per node in JSON)
    snapshot_mb = N * 500 / 1e6;
    % WAL entry size (~200B per mutation)
    wal_entry_b = 200;
    % Mutations per second (steady state)
    mutations_sec = N * churn_rate_per_min / 60 + N / keepalive_s * 0;  % heartbeat is atomic, no WAL
    % WAL growth rate
    wal_growth_mb_min = mutations_sec * wal_entry_b * 60 / 1e6;
    % Time between compactions
    compaction_interval = 60;  % Phase 2
    wal_size_at_compact = mutations_sec * wal_entry_b * compaction_interval / 1e6;

    fprintf('  %-8s: snapshot=%.1fMB  mutations=%.1f/s  WAL_growth=%.3fMB/min  WAL_at_compact=%.3fMB\n', ...
        N_labels{ni}, snapshot_mb, mutations_sec, wal_growth_mb_min, wal_size_at_compact);
end

%% =====================================================================
%% 7. REPLICATION ANALYSIS
%% =====================================================================

fprintf('\n--- 7. REPLICATION BANDWIDTH ---\n\n');

for ni = 1:length(N_points)
    N = N_points(ni);
    snapshot_mb = N * 500 / 1e6;
    mutations_sec = N * churn_rate_per_min / 60;
    delta_bandwidth_kbs = mutations_sec * 200 / 1000;  % KB/s for delta replication

    fprintf('  %-8s: full_snapshot=%.1fMB/push  delta=%.1fKB/s (%.0fx smaller per-mutation)\n', ...
        N_labels{ni}, snapshot_mb, delta_bandwidth_kbs, snapshot_mb * 1000 / max(0.2, delta_bandwidth_kbs));
end

%% =====================================================================
%% 8. CRITICAL PATH ANALYSIS PER PHASE
%% =====================================================================

fprintf('\n--- 8. CRITICAL PATH (What Actually Limits Each Phase) ---\n\n');

fprintf('PHASE 1 (Target: 100K on c2-standard-8):\n');
N = 100000;
hb_rate = N / keepalive_s;
hb_cpu = hb_rate * ed25519Verify_us * 1e-6;
save_lock_ms = N * 5e-6 * 1000;  % Phase 1 optimized save
save_freq = 1;
save_lock_pct = save_lock_ms / 1000 * 100;
fprintf('  Heartbeat rate:        %.0f/sec using %.1f cores (of %d)\n', hb_rate, hb_cpu, cores_p1);
fprintf('  Snapshot lock hold:    %.1f ms every %ds (%.2f%% lock time)\n', save_lock_ms, save_freq, save_lock_pct);
fprintf('  Bottleneck:            HEARTBEAT CPU (%.0f%% of capacity)\n', hb_cpu / cores_p1 * 100);
if hb_cpu > cores_p1 * 0.8
    fprintf('  *** WARNING: >80%% CPU on heartbeat verify alone ***\n');
end
fprintf('\n');

fprintf('PHASE 2 (Target: 300K on c2-standard-16):\n');
N = 300000;
hb_rate = N / keepalive_s;
hb_cpu = hb_rate * ed25519Verify_us * 1e-6;
save_lock_ms = N * 0.5e-6 * 1000;
save_freq = 60;  % WAL compaction interval
fprintf('  Heartbeat rate:        %.0f/sec using %.1f cores (of %d)\n', hb_rate, hb_cpu, cores_p2);
fprintf('  Snapshot lock hold:    %.1f ms every %ds (%.4f%% lock time)\n', save_lock_ms, save_freq, save_lock_ms/save_freq/10);
fprintf('  Sharded: heartbeat, resolve, lookup all use per-shard locks\n');
fprintf('  Bottleneck:            HEARTBEAT CPU (%.0f%% of capacity)\n', hb_cpu / cores_p2 * 100);
if hb_cpu > cores_p2 * 0.8
    fprintf('  *** WARNING: >80%% CPU on heartbeat verify alone ***\n');
end
fprintf('\n');

fprintf('PHASE 3 (Target: 1M on c2-standard-30):\n');
N = 1000000;
hb_rate = N / keepalive_p3_s;  % 60s interval
hb_cpu = hb_rate * (ed25519Verify_us / heartbeatVerifySkipN) * 1e-6;
save_lock_ms = N * 0.5e-6 * 1000;
save_freq = 60;
fprintf('  Heartbeat rate:        %.0f/sec using %.1f cores (of %d)\n', hb_rate, hb_cpu, cores_p3);
fprintf('  Verify skip (1/%d):    %.0f actual verifies/sec\n', heartbeatVerifySkipN, hb_rate / heartbeatVerifySkipN);
fprintf('  Snapshot lock hold:    %.1f ms every %ds\n', save_lock_ms, save_freq);
fprintf('  Bottleneck:            NONE (%.0f%% CPU headroom)\n', (1 - hb_cpu/cores_p3)*100);
fprintf('\n');

%% =====================================================================
%% 9. LATENCY COMPARISON TABLE (with storms)
%% =====================================================================

fprintf('--- 9. LATENCY SUMMARY (Steady State vs Storm) ---\n\n');

fprintf('%-35s | %10s | %10s | %10s\n', 'Scenario', 'Phase 1', 'Phase 2', 'Phase 3');
fprintf('%s\n', repmat('-', 1, 75));

% Steady-state register (dominated by RTT)
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', 'Register (steady state)', ...
    reg_total_baseline, reg_total_baseline, reg_total_baseline);

% Register during restart storm (1000/sec throttled)
wait_1000 = handleRegister_us / (1 - 1000 * handleRegister_us * 1e-6) * 1e-3;  % ms
wait_1000_shard = 5 / (1 - 1000 * 5e-6) * 1e-3;
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', 'Register (restart, 1K/s throttle)', ...
    reg_total_baseline + wait_1000, reg_total_baseline + wait_1000_shard, reg_total_baseline + wait_1000_shard);

% Register during 16.7K/sec unmitigated storm (1M nodes)
rate_16k = 1000000 / 60;
rho_16k = rate_16k * handleRegister_us * 1e-6;
if rho_16k < 1
    wait_16k = handleRegister_us * 1e-6 / (1 - rho_16k) * 1000;
else
    wait_16k = 9999;
end
rho_16k_s = rate_16k * 5e-6;
wait_16k_s = 5e-6 / (1 - rho_16k_s) * 1000;
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', 'Register (storm, 16.7K/s unreg)', ...
    reg_total_baseline + wait_16k, reg_total_baseline + wait_16k_s, reg_total_baseline + wait_16k_s);

% Message steady state (uncached)
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', '1KB Msg (uncached resolve)', ...
    msg_total_baseline, msg_total_baseline, msg_total_baseline - msg_resolve + msg_resolve);

% Message cached
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', '1KB Msg (cached resolve)', ...
    msg_total_baseline, msg_cached, msg_cached);

% Message during cron storm (200K agents resolving)
storm_resolve_rate = 200000 * 5 / 30;  % 33.3K/sec
resolve_verify_latency = ed25519Verify_us / 1000;  % ms
queue_depth_p1 = storm_resolve_rate * (ed25519Verify_us + resolveRLock_us) * 1e-6;
if queue_depth_p1 < 1
    storm_resolve_wait_p1 = (ed25519Verify_us + resolveRLock_us) * 1e-6 / (1 - queue_depth_p1) * 1000;
else
    storm_resolve_wait_p1 = 9999;
end
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', '1KB Msg (cron storm, 33K resolves/s)', ...
    msg_total_baseline + storm_resolve_wait_p1, msg_cached, msg_cached);

% File
ft_1mb = file_transfer_time(1e6, rtt_tunnel_ms/1000, MSS, initialCwnd_bytes, initialSsthresh_bytes) * 1000;
fprintf('%-35s | %8.1f ms | %8.1f ms | %8.1f ms\n', '1MB File (steady state)', ...
    msg_resolve + 1.5*rtt_tunnel_ms + ft_1mb, ...
    msg_resolve + 1.5*rtt_tunnel_ms + ft_1mb, ...
    1.5*rtt_tunnel_ms + ft_1mb);

%% =====================================================================
%% 10. MEMORY BUDGET
%% =====================================================================

fprintf('\n--- 10. MEMORY BUDGET ---\n\n');

fprintf('%-25s | %10s | %10s | %10s | %10s\n', 'Component', '12.7K', '100K', '300K', '1M');
fprintf('%s\n', repmat('-', 1, 72));

for ni = [3, 5, 6, 8]  % 12.7K, 100K, 300K, 1M
    N = N_points(ni);
    mem_goroutine = N * 2048 / 1e9;
    mem_tcp = N * 8192 / 1e9;
    mem_nodeinfo = N * 300 / 1e9;
    mem_snapshot = N * 500 / 1e9;  % during compaction
    mem_index = N * 100 / 1e9;  % pubKeyIdx + ownerIdx + hostnameIdx
    mem_gc = (mem_goroutine + mem_tcp + mem_nodeinfo + mem_index) * 0.25;
    mem_total = mem_goroutine + mem_tcp + mem_nodeinfo + mem_snapshot + mem_index + mem_gc;

    if ni == 3
        fprintf('%-25s | %8.2f GB |', 'Goroutine stacks', mem_goroutine);
    elseif ni == 5
        mem_goroutine2 = N_points(5) * 2048 / 1e9;
        fprintf(' %8.2f GB |', mem_goroutine2);
    elseif ni == 6
        mem_goroutine3 = N_points(6) * 2048 / 1e9;
        fprintf(' %8.2f GB |', mem_goroutine3);
    else
        mem_goroutine4 = N_points(8) * 2048 / 1e9;
        fprintf(' %8.2f GB\n', mem_goroutine4);
    end
end

% Simpler table format
fprintf('\n');
for ni_idx = 1:4
    ni_map = [3, 5, 6, 8];
    ni = ni_map(ni_idx);
    N = N_points(ni);
    mem_goroutine = N * 2048 / 1e9;
    mem_tcp = N * 8192 / 1e9;
    mem_nodeinfo = N * 300 / 1e9;
    mem_snapshot = N * 500 / 1e9;
    mem_index = N * 100 / 1e9;
    mem_gc = (mem_goroutine + mem_tcp + mem_nodeinfo + mem_index) * 0.25;
    mem_total = mem_goroutine + mem_tcp + mem_nodeinfo + mem_snapshot + mem_index + mem_gc;

    fprintf('%s nodes:\n', N_labels{ni});
    fprintf('  Goroutine stacks:  %6.2f GB\n', mem_goroutine);
    fprintf('  TCP buffers:       %6.2f GB\n', mem_tcp);
    fprintf('  NodeInfo structs:  %6.2f GB\n', mem_nodeinfo);
    fprintf('  Index maps:        %6.2f GB\n', mem_index);
    fprintf('  Snapshot (burst):  %6.2f GB\n', mem_snapshot);
    fprintf('  GC overhead (~25%%): %5.2f GB\n', mem_gc);
    fprintf('  TOTAL:             %6.2f GB', mem_total);
    vm_ram = [0 0 32 0 64 128 0 128];
    if vm_ram(ni) > 0
        fprintf('  (of %d GB VM = %.0f%%)', vm_ram(ni), mem_total/vm_ram(ni)*100);
    end
    fprintf('\n\n');
end

%% =====================================================================
%% 11. NETWORK BANDWIDTH
%% =====================================================================

fprintf('--- 11. NETWORK BANDWIDTH ---\n\n');

for ni_idx = 1:4
    ni_map = [3, 5, 6, 8];
    ni = ni_map(ni_idx);
    N = N_points(ni);

    hb_rate = N / keepalive_s;
    hb_bw = hb_rate * (jsonHeartbeat_bytes + jsonHBResp_bytes);

    resolve_rate = N * resolve_freq_per_node;
    resolve_bw = resolve_rate * 350;  % ~350B per resolve round-trip

    reg_rate = N * churn_rate_per_min / 60;
    reg_bw = reg_rate * 400;  % ~400B per register round-trip

    total_bw = hb_bw + resolve_bw + reg_bw;

    fprintf('%s nodes:\n', N_labels{ni});
    fprintf('  Heartbeat:    %8.0f/sec × 200B = %8.2f MB/s\n', hb_rate, hb_bw/1e6);
    fprintf('  Resolve:      %8.1f/sec × 350B = %8.2f MB/s\n', resolve_rate, resolve_bw/1e6);
    fprintf('  Registration: %8.1f/sec × 400B = %8.4f MB/s\n', reg_rate, reg_bw/1e6);
    fprintf('  TOTAL:                             %8.2f MB/s = %.0f Mbps (of 10 Gbps)\n', ...
        total_bw/1e6, total_bw*8/1e6);
    fprintf('\n');
end

%% =====================================================================
%% 12. AIMD THROUGHPUT DETAILS
%% =====================================================================

fprintf('--- 12. AIMD TRANSFER MODEL ---\n\n');

rtts_ms = [1, 5, 20, 30, 50, 100];
file_sz = 1e6;  % 1MB

fprintf('1MB file transfer (no loss):\n');
fprintf('%-10s | %12s | %12s | %12s\n', 'RTT', 'Time', 'Avg Tput', 'Segments');
fprintf('%s\n', repmat('-', 1, 55));

for ri = 1:length(rtts_ms)
    rtt_val = rtts_ms(ri) / 1000;
    ft = file_transfer_time(file_sz, rtt_val, MSS, initialCwnd_bytes, initialSsthresh_bytes);
    avg_tput = file_sz / ft / 1e6;
    segs = ceil(file_sz / MSS);
    fprintf('%-10s | %10.1f ms | %10.1f MB/s | %10d\n', ...
        sprintf('%dms', rtts_ms(ri)), ft*1000, avg_tput, segs);
end

fprintf('\nSlow start ramp (30ms RTT, 1MB file):\n');
rtt_val = 0.030;
cwnd = initialCwnd_bytes;
transferred = 0;
rtt_num = 0;
fprintf('  RTT# | cwnd (KB) | Sent this RTT | Total sent | Phase\n');
fprintf('  %s\n', repmat('-', 1, 60));
while transferred < file_sz
    chunk = min(cwnd, file_sz - transferred);
    transferred = transferred + chunk;
    rtt_num = rtt_num + 1;
    if cwnd < initialSsthresh_bytes
        phase_str = 'slow-start';
    else
        phase_str = 'cong-avoid';
    end
    fprintf('  %4d | %9.1f | %13.0f | %10.0f | %s\n', ...
        rtt_num, cwnd/1024, chunk, transferred, phase_str);

    if cwnd < initialSsthresh_bytes
        cwnd = min(cwnd * 2, initialSsthresh_bytes);
    else
        cwnd = cwnd + MSS * MSS / cwnd;
    end
    cwnd = min(cwnd, maxCwnd_bytes);
end
fprintf('  Total RTTs: %d (%.1f ms)\n', rtt_num, rtt_num * rtt_val * 1000);

%% =====================================================================
%% 13. PHASE DIFFERENTIATION SUMMARY
%% =====================================================================

fprintf('\n--- 13. WHY EACH PHASE MATTERS ---\n\n');

fprintf('Current (12.7K nodes on e2-standard-4):\n');
fprintf('  Everything is fine. Lock util <0.01%%, CPU <20%%.\n\n');

fprintf('Phase 1 changes that matter at 100K:\n');
fprintf('  1. flushSave: lock hold drops from %.1fms to %.1fms (%.0fx)\n', ...
    100000*5e-6*1000, 100000*0.5e-6*1000, 5/0.5);
fprintf('     -> Without this, snapshot at 100K holds write lock for %.1fms EVERY SECOND\n', 100000*5e-6*1000);
fprintf('     -> All writes (register, reap) stall during that window\n');
fprintf('  2. Chunked reap: instead of scanning 100K under write lock (%.1fms),\n', 100000*1e-6*1000);
fprintf('     scan 10K chunks (%.1fms each)\n', 10000*1e-6*1000);
fprintf('  3. Verify outside lock: RLock hold drops from ~30us to ~2us per resolve\n');
fprintf('  4. Accept throttle: prevents 100K simultaneous reconnects from saturating lock\n');
fprintf('\n');

fprintf('Phase 2 changes that matter at 300K:\n');
fprintf('  1. WAL: snapshot every 60s instead of 1s. Lock held %.1fms/60s instead of %.1fms/1s\n', ...
    300000*0.5e-6*1000, 300000*0.5e-6*1000);
fprintf('     -> 60x reduction in snapshot lock frequency\n');
fprintf('  2. Sharded locks: heartbeat+resolve use per-shard lock, ZERO global contention\n');
fprintf('     -> Registration storms don''t block heartbeat processing\n');
fprintf('  3. Delta replication: push ~1KB/mutation instead of %.0fMB full snapshot\n', 300000*500/1e6);
fprintf('  4. Resolve cache: cron storms hit cache (80%%+) instead of registry\n');
fprintf('\n');

fprintf('Phase 3 changes that matter at 1M:\n');
fprintf('  1. 60s heartbeat: rate drops from %.0f/s to %.0f/s (2x)\n', 1e6/30, 1e6/60);
fprintf('  2. Verify skip: effective verify rate %.0f/s (%.0fx reduction)\n', ...
    1e6/60/heartbeatVerifySkipN, heartbeatVerifySkipN);
fprintf('  3. Binary wire: 3x less CPU for encode/decode\n');
fprintf('  4. Combined: heartbeat CPU drops from %.1f cores to %.1f cores\n', ...
    1e6/30 * ed25519Verify_us * 1e-6, 1e6/60 * (ed25519Verify_us/heartbeatVerifySkipN) * 1e-6);
fprintf('\n');

fprintf('========================================\n');
fprintf('  DIAGNOSTICS COMPLETE\n');
fprintf('========================================\n');

%% =====================================================================
%% HELPER FUNCTIONS
%% =====================================================================

function total_s = file_transfer_time(file_size, rtt_s, mss, cwnd0, ssthresh)
    transferred = 0;
    cwnd = cwnd0;
    t = 0;
    while transferred < file_size
        chunk = min(cwnd, file_size - transferred);
        transferred = transferred + chunk;
        t = t + rtt_s;
        if cwnd < ssthresh
            cwnd = min(cwnd * 2, ssthresh);
        else
            cwnd = cwnd + mss * mss / cwnd;
        end
        cwnd = min(cwnd, 1024*1024);
    end
    total_s = t;
end

function result = ternary(condition, true_val, false_val)
    if condition
        result = true_val;
    else
        result = false_val;
    end
end

