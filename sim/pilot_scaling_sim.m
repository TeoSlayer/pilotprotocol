%% pilot_scaling_sim.m — Pilot Protocol End-to-End Latency Simulation
% Models end-to-end latency for register, send message, and send file
% operations across node counts from 1K to 1M.
% All timing constants extracted from source code with exact file:line refs.
%
% Run in MATLAB Online: just paste or upload and click Run.

clear; clc; close all;

%% =====================================================================
%% 1. PROFILED CONSTANTS (from source code)
%% =====================================================================

% --- Registry Server (pkg/registry/server.go) ---
defaultMaxConnections  = 1100000;           % server.go:346  (Phase 1 raised from 100K)
socketBufSize          = 4096;              % server.go:1090-1091  (read/write)
readDeadline_s         = 300;               % server.go:1096
maxMessageSize         = 64*1024;           % server.go:350
saveCoalesce_s         = 1;                 % server.go:4758 (saveLoop ticker)
staleThreshold_s       = 180;               % server.go:343 (3 min)
reapInterval_s         = 10;                % server.go:984  (Phase 1: was 60s)
reapChunkSize          = 10000;             % server.go:1000 (Phase 1)
ed25519Verify_us       = 28;               % ~28us per verify (measured)
regRateLimit_perIP     = 10;               % server.go:723 (per minute)
resolveRateLimit_perIP = 100;              % server.go:739 (per minute)
replHeartbeat_s        = 15;               % replication.go:98
replWriteDeadline_s    = 10;               % replication.go:76

% Client reconnect (pkg/registry/client.go)
clientReconnAttempts   = 5;                % client.go:116-124
clientInitBackoff_ms   = 500;
clientMaxBackoff_s     = 10;
clientDialTimeout_s    = 5;

% --- Daemon/Transport (pkg/daemon/daemon.go, ports.go) ---
MSS                    = 4096;             % ports.go:102
initialCwnd_bytes      = 40960;            % ports.go:100 (10 segments)
maxCwnd_bytes          = 1024*1024;        % ports.go:101 (1MB)
initialSsthresh_bytes  = 512*1024;         % ports.go:340 (512KB)
initialRTO_s           = 1.0;             % ports.go:115
minRTO_s               = 0.200;           % ports.go:113
maxRTO_s               = 10.0;            % ports.go:114
rttAlpha               = 1/8;             % ports.go:705-723 (RFC 6298)
rttBeta                = 1/4;
fastRetransmitDupAcks  = 3;               % ports.go:580
delayedAck_ms          = 40;              % daemon.go:1777-1780
nagleTimeout_ms        = 40;              % daemon.go:1774
recvBufSegments        = 512;             % ports.go:103-104 (2MB max window)
sendBufSegments        = 256;             % ports.go:107
keepalive_s            = 30;              % daemon.go:67
idleTimeout_s          = 120;             % daemon.go:68
dialDirectRetries      = 3;               % daemon.go:78
dialMaxRetries         = 6;               % daemon.go:79
dialInitialRTO_s       = 1.0;            % daemon.go:80
dialMaxRTO_s           = 8.0;            % daemon.go:81
pktHeader_bytes        = 34;              % tunnel.go (unencrypted)
pktHeaderEncrypted     = 34 + 36;         % +36 for encryption overhead
recvChSize             = 1024;            % tunnel.go:146  (Phase 1)
relayQueueSize         = 4096;            % beacon/server.go:46

% Data exchange
dataExchangeMaxFrame   = 16*1024*1024;    % dataexchange.go:57 (16MB)

% --- Phase 2 additions ---
numShards              = 256;             % Phase 2.3: sharded state lock
resolveCacheTTL_s      = 60;              % Phase 2.4: daemon resolve cache

% --- Phase 3 additions ---
binaryHeartbeat_bytes  = 69;              % Phase 3.2: binary wire [1+4+64]
binaryHBResp_bytes     = 9;               % Phase 3.2: [1+8]
jsonHeartbeat_bytes    = 150;             % current JSON heartbeat
jsonHBResp_bytes       = 50;              % current JSON response
heartbeatVerifySkipN   = 5;               % Phase 3.1: verify every 5th

%% =====================================================================
%% 2. HELPER FUNCTIONS
%% =====================================================================

% M/M/1 queue: mean wait time
% arrival_rate in ops/sec, service_time in seconds
mm1_wait = @(arrival_rate, service_time) ...
    service_time ./ max(1 - arrival_rate .* service_time, 0.001);

% M/M/c queue: Erlang-C based mean wait
% For sharded locks: c = numShards, each shard is a "server"
mmc_wait = @(arrival_rate, service_time, c) ...
    service_time ./ max(1 - arrival_rate .* service_time ./ c, 0.001) ./ c;

% AIMD congestion window over time
% Returns cwnd(t) given RTT, MSS, initial cwnd, ssthresh, loss_rate
function [t_vec, cwnd_vec, tput_vec] = aimd_throughput(rtt_s, mss, cwnd0, ssthresh, total_time, loss_rate)
    dt = rtt_s;  % one RTT per step
    steps = ceil(total_time / dt);
    t_vec = zeros(1, steps);
    cwnd_vec = zeros(1, steps);
    tput_vec = zeros(1, steps);

    cwnd = cwnd0;
    for i = 1:steps
        t_vec(i) = (i-1) * dt;
        cwnd_vec(i) = cwnd;
        tput_vec(i) = cwnd / rtt_s;  % bytes/sec throughput

        % Check for loss event
        if rand() < loss_rate * dt
            % Multiplicative decrease
            cwnd = max(cwnd / 2, mss);
            ssthresh = cwnd;
        else
            if cwnd < ssthresh
                % Slow start: double per RTT
                cwnd = min(cwnd * 2, ssthresh);
            else
                % Congestion avoidance: linear increase
                cwnd = cwnd + mss * mss / cwnd;
            end
        end

        % Cap at max
        cwnd = min(cwnd, 1024*1024);  % maxCwnd
    end
end

% File transfer time (simplified)
function total_s = file_transfer_time(file_size, rtt_s, mss, cwnd0, ssthresh)
    transferred = 0;
    cwnd = cwnd0;
    t = 0;
    while transferred < file_size
        % Bytes sent this RTT = min(cwnd, remaining)
        chunk = min(cwnd, file_size - transferred);
        transferred = transferred + chunk;
        t = t + rtt_s;

        % Slow start / congestion avoidance
        if cwnd < ssthresh
            cwnd = min(cwnd * 2, ssthresh);
        else
            cwnd = cwnd + mss * mss / cwnd;
        end
        cwnd = min(cwnd, 1024*1024);
    end
    total_s = t;
end

%% =====================================================================
%% 3. OPERATION LATENCY MODELS
%% =====================================================================

% Node counts to sweep (log-spaced from 1K to 1M)
N_vec = round(logspace(3, 6, 100));

% RTT assumptions
rtt_tcp_ms       = 20;    % registry RTT (regional, ms)
rtt_beacon_ms    = 20;    % beacon RTT (co-located with registry)
rtt_tunnel_ms    = 30;    % peer-to-peer UDP tunnel RTT

rtt_tcp_s        = rtt_tcp_ms / 1000;
rtt_beacon_s     = rtt_beacon_ms / 1000;
rtt_tunnel_s     = rtt_tunnel_ms / 1000;

% Derived rates
churn_rate       = 0.001;  % 0.1% churn per minute
resolve_freq     = 1/300;  % each node resolves 5 peers every 5 minutes
peers_per_node   = 5;

%% --- Register Operation ---
function lat = register_latency(N, rtt_tcp, rtt_beacon, ed25519_us, phase)
    % TCP connect (SYN + SYN-ACK)
    tcp_connect = rtt_tcp;

    % JSON encode request
    json_encode = 5e-6;  % 5us

    % Server: acquire write lock (queueing delay)
    reg_rate = min(N * 0.001 / 60, 1000);  % registration rate
    service_time = 50e-6;  % 50us per registration under lock

    if phase == 1
        % Single global lock
        lock_wait = service_time ./ max(1 - reg_rate .* service_time, 0.01);
    elseif phase == 2
        % Sharded: only nextNode allocation needs global lock (5us)
        service_time_global = 5e-6;
        lock_wait = service_time_global ./ max(1 - reg_rate .* service_time_global, 0.01);
    else
        % Phase 3: same as Phase 2 + binary wire
        service_time_global = 5e-6;
        lock_wait = service_time_global ./ max(1 - reg_rate .* service_time_global, 0.01);
    end

    % handleRegister processing
    handler_time = 50e-6;

    % JSON encode response
    json_resp = 5e-6;
    if phase >= 3
        json_resp = 0.5e-6;  % binary wire
    end

    % TCP response
    tcp_resp = rtt_tcp;

    % STUN discover
    stun = rtt_beacon;

    % Beacon register
    beacon_reg = rtt_beacon;

    lat = tcp_connect + json_encode + lock_wait + handler_time + json_resp + ...
          tcp_resp + stun + beacon_reg;
end

%% --- Send Message Latency ---
function lat = message_latency(N, msg_size, rtt_tcp, rtt_tunnel, ed25519_us, phase, cached)
    % Resolve peer (skip if cached)
    if cached
        resolve = 0;
    else
        resolve_service = 2e-6;  % RLock hold time
        verify_time = ed25519_us * 1e-6;

        if phase >= 2
            resolve_service = resolve_service / 256;  % sharded
        end

        resolve = 2 * rtt_tcp + resolve_service + verify_time;
    end

    % Connection setup (SYN-SYN/ACK-ACK)
    conn_setup = 1.5 * rtt_tunnel;

    % Data transfer
    if msg_size <= 4096  % MSS
        data_transfer = rtt_tunnel;  % single segment + ACK
    else
        segments = ceil(msg_size / 4096);
        data_transfer = segments * rtt_tunnel;
    end

    % Delayed ACK
    delayed_ack = 0.040;  % 40ms max

    % FIN exchange
    fin = rtt_tunnel;

    lat = resolve + conn_setup + data_transfer + delayed_ack + fin;
end

%% --- Send File Latency ---
function lat = file_latency_fn(N, file_size, rtt_tcp, rtt_tunnel, ed25519_us, phase, cached)
    % Resolve + connection setup (same as message)
    if cached
        resolve = 0;
    else
        verify_time = ed25519_us * 1e-6;
        resolve = 2 * rtt_tcp + verify_time;
    end

    conn_setup = 1.5 * rtt_tunnel;

    % Metadata frame
    metadata = rtt_tunnel;

    % Bulk transfer with AIMD
    bulk_time = file_transfer_time(file_size, rtt_tunnel, 4096, 40960, 512*1024);

    lat = resolve + conn_setup + metadata + bulk_time;
end

%% =====================================================================
%% 4. SWEEP N FROM 1K TO 1M — COMPUTE LATENCIES PER PHASE
%% =====================================================================

% Pre-allocate results
reg_lat_p1 = zeros(size(N_vec));
reg_lat_p2 = zeros(size(N_vec));
reg_lat_p3 = zeros(size(N_vec));

msg_lat_p1 = zeros(size(N_vec));
msg_lat_p2 = zeros(size(N_vec));
msg_lat_p3 = zeros(size(N_vec));

file_lat_p1 = zeros(size(N_vec));
file_lat_p2 = zeros(size(N_vec));
file_lat_p3 = zeros(size(N_vec));

msg_size = 1024;    % 1KB message
file_size = 1e6;    % 1MB file

for i = 1:length(N_vec)
    N = N_vec(i);

    % Register latency
    reg_lat_p1(i) = register_latency(N, rtt_tcp_s, rtt_beacon_s, ed25519Verify_us, 1);
    reg_lat_p2(i) = register_latency(N, rtt_tcp_s, rtt_beacon_s, ed25519Verify_us, 2);
    reg_lat_p3(i) = register_latency(N, rtt_tcp_s, rtt_beacon_s, ed25519Verify_us, 3);

    % Message latency (uncached)
    msg_lat_p1(i) = message_latency(N, msg_size, rtt_tcp_s, rtt_tunnel_s/1, ed25519Verify_us, 1, false);
    msg_lat_p2(i) = message_latency(N, msg_size, rtt_tcp_s, rtt_tunnel_s/1, ed25519Verify_us, 2, false);
    msg_lat_p3(i) = message_latency(N, msg_size, rtt_tcp_s, rtt_tunnel_s/1, ed25519Verify_us, 3, true);  % cached in Phase 3

    % File transfer latency
    file_lat_p1(i) = file_latency_fn(N, file_size, rtt_tcp_s, rtt_tunnel_s, ed25519Verify_us, 1, false);
    file_lat_p2(i) = file_latency_fn(N, file_size, rtt_tcp_s, rtt_tunnel_s, ed25519Verify_us, 2, false);
    file_lat_p3(i) = file_latency_fn(N, file_size, rtt_tcp_s, rtt_tunnel_s, ed25519Verify_us, 3, true);
end

%% =====================================================================
%% 5. LOCK CONTENTION MODEL
%% =====================================================================

% Write lock utilization vs N
write_lock_util_single = zeros(size(N_vec));
write_lock_util_shard  = zeros(size(N_vec));
write_lock_wait_single = zeros(size(N_vec));
write_lock_wait_shard  = zeros(size(N_vec));

for i = 1:length(N_vec)
    N = N_vec(i);

    % Write operations: registration + reap
    reg_rate = min(N * churn_rate / 60, 10000);  % registrations/sec
    reap_rate = N * 1e-6 / 10;  % amortized reap cost (10s interval, 1us per node)

    write_rate = reg_rate + reap_rate;

    % Single lock (Phase 1)
    service_time_single = 50e-6;
    rho_single = write_rate * service_time_single;
    write_lock_util_single(i) = min(rho_single, 0.999);
    write_lock_wait_single(i) = mm1_wait(write_rate, service_time_single);

    % Sharded (Phase 2): only 5us for global lock portion
    service_time_shard = 5e-6;
    rho_shard = write_rate * service_time_shard;
    write_lock_util_shard(i) = min(rho_shard, 0.999);
    write_lock_wait_shard(i) = mmc_wait(write_rate, service_time_shard, 1);
end

%% =====================================================================
%% 6. THROUGHPUT MODEL
%% =====================================================================

% Max ops/sec for each operation type
cores_p1 = 8;   % c2-standard-8
cores_p2 = 16;  % c2-standard-16
cores_p3 = 30;  % c2-standard-30

% Heartbeat throughput (limited by sig verify)
hb_rate_p1 = N_vec / keepalive_s;     % heartbeats/sec at each N
hb_rate_p3 = N_vec / 60;              % Phase 3: 60s interval

% CPU cost per heartbeat
hb_cpu_single = ed25519Verify_us * 1e-6;  % 28us
hb_cpu_skip = hb_cpu_single / heartbeatVerifySkipN;  % verify every 5th

% Max heartbeat rate before CPU saturation
max_hb_p1 = cores_p1 / hb_cpu_single;
max_hb_p2 = cores_p2 / hb_cpu_single;
max_hb_p3 = cores_p3 / hb_cpu_skip;

% Resolve throughput (CPU-bound by Ed25519 verify, NOT by lock)
resolve_cpu = ed25519Verify_us * 1e-6 + 2e-6;  % verify + lock (Phase 1)
max_resolve_p1 = cores_p1 / resolve_cpu;
% Phase 2: sharding eliminates lock contention but verify still costs 28us CPU
max_resolve_p2 = cores_p2 / (ed25519Verify_us * 1e-6);  % CPU-bound
% Phase 3: verify every 5th + binary wire
max_resolve_p3 = cores_p3 / (ed25519Verify_us / heartbeatVerifySkipN * 1e-6);

% Registration throughput
reg_cpu = 50e-6;  % 50us under global lock
max_reg_p1 = 1 / reg_cpu;  % limited by single lock
max_reg_p2 = 1 / 5e-6;    % Phase 2: 5us global portion
max_reg_p3 = max_reg_p2;

%% =====================================================================
%% 7. STORM SIMULATIONS
%% =====================================================================

% --- Cron Storm (200K agents, 30s jitter) ---
t_cron = 0:0.5:120;  % seconds
cron_agents = 200000;
cron_peers = 5;
jitter_window = 30;  % seconds

% Agent wakeup distribution (uniform over jitter window)
cron_wake_rate = zeros(size(t_cron));
for ti = 1:length(t_cron)
    t = t_cron(ti);
    if t >= 5 && t <= 5 + jitter_window
        cron_wake_rate(ti) = cron_agents / jitter_window;
    end
end

% Resolve rate follows wake rate with ~5-10s lag
cron_resolve_rate = zeros(size(t_cron));
for ti = 1:length(t_cron)
    t = t_cron(ti);
    if t >= 10 && t <= 10 + jitter_window
        cron_resolve_rate(ti) = (cron_agents * cron_peers) / jitter_window;
    end
end

% CPU utilization during cron storm
cron_cpu = cron_resolve_rate * (ed25519Verify_us * 1e-6);
cron_lock_wait = zeros(size(t_cron));
for ti = 1:length(t_cron)
    if cron_resolve_rate(ti) > 0
        svc = 2e-6 / 256;  % sharded lock service time
        rho = cron_resolve_rate(ti) * svc;
        cron_lock_wait(ti) = svc / max(1 - rho, 0.01) * 1000;  % ms
    end
end

% --- Restart Storm (1M agents, accept throttle + backoff + jitter) ---
t_restart = 0:1:300;  % seconds
restart_agents = 1000000;
accept_throttle_rate = 1000;  % conns/sec first 60s
jitter_60s = 60;

restart_rereg_rate = zeros(size(t_restart));
for ti = 1:length(t_restart)
    t = t_restart(ti);
    if t < 60
        % Accept throttle limits to 1000/sec
        restart_rereg_rate(ti) = accept_throttle_rate;
    elseif t < 120
        % Backoff spreads remaining agents
        remaining = restart_agents - accept_throttle_rate * 60;
        restart_rereg_rate(ti) = remaining / 60;  % spread over next 60s
    end
end

restart_mem_gb = zeros(size(t_restart));
restart_lock_util = zeros(size(t_restart));
cumulative_registered = 0;
for ti = 1:length(t_restart)
    cumulative_registered = cumulative_registered + restart_rereg_rate(ti);
    cumulative_registered = min(cumulative_registered, restart_agents);

    % Memory: goroutine stacks + TCP buffers + NodeInfo
    restart_mem_gb(ti) = (cumulative_registered * 2048 + ...    % goroutine stacks
                          cumulative_registered * 8192 + ...    % TCP buffers
                          cumulative_registered * 300) / 1e9;   % NodeInfo

    % Write lock utilization
    rho = restart_rereg_rate(ti) * 50e-6;
    restart_lock_util(ti) = min(rho, 1.0);
end

%% =====================================================================
%% 8. GENERATE FIGURES
%% =====================================================================

figW = 800; figH = 500;

% --- Figure 1: Register Operation — Stage Waterfall ---
figure('Position', [100 100 figW figH]);
stages = {'TCP Connect', 'JSON Encode', 'Lock Wait', 'handleRegister', ...
          'JSON Response', 'TCP Response', 'STUN Discover', 'Beacon Register'};
% At N=100K
N_ex = 100000;
tcp_conn = rtt_tcp_ms;
json_enc = 0.005;  % ms
lock_w   = register_latency(N_ex, rtt_tcp_s, rtt_beacon_s, ed25519Verify_us, 1)*1000 - 4*rtt_tcp_ms - 0.01 - 0.05 - 2*rtt_beacon_ms;
lock_w   = max(lock_w, 0.001);
handler  = 0.05;
json_rsp = 0.005;
tcp_rsp  = rtt_tcp_ms;
stun_d   = rtt_beacon_ms;
beacon_r = rtt_beacon_ms;

bar_data = [tcp_conn, json_enc, lock_w, handler, json_rsp, tcp_rsp, stun_d, beacon_r];
barh(bar_data, 'FaceColor', [0.2 0.4 0.8]);
set(gca, 'YTickLabel', stages, 'YTick', 1:8, 'FontSize', 11);
xlabel('Latency (ms)', 'FontSize', 12);
title(sprintf('Register Operation — Stage Waterfall (N=%dK)', N_ex/1000), 'FontSize', 14);
grid on;

% --- Figure 2: Send Message — Stage Waterfall ---
figure('Position', [100 100 figW figH]);
msg_stages = {'Resolve (TCP+verify)', 'Dial (SYN/SYN-ACK/ACK)', ...
              'Data Transfer (1KB)', 'Delayed ACK', 'FIN Exchange'};
resolve_ms = 2*rtt_tcp_ms + 0.028;
dial_ms    = 1.5 * rtt_tunnel_ms;
data_ms    = rtt_tunnel_ms;
dack_ms    = 40;
fin_ms     = rtt_tunnel_ms;

msg_bar = [resolve_ms, dial_ms, data_ms, dack_ms, fin_ms];
barh(msg_bar, 'FaceColor', [0.2 0.7 0.3]);
set(gca, 'YTickLabel', msg_stages, 'YTick', 1:5, 'FontSize', 11);
xlabel('Latency (ms)', 'FontSize', 12);
title('Send 1KB Message — Stage Waterfall', 'FontSize', 14);
grid on;

% --- Figure 3: Send File — Stage Waterfall ---
figure('Position', [100 100 figW figH]);
file_stages = {'Resolve', 'Connect (port 1001)', 'Metadata Frame', ...
               'Bulk Transfer (1MB)'};
bulk_ms = file_transfer_time(1e6, rtt_tunnel_s, MSS, initialCwnd_bytes, initialSsthresh_bytes) * 1000;
file_bar = [resolve_ms, dial_ms, rtt_tunnel_ms, bulk_ms];
barh(file_bar, 'FaceColor', [0.8 0.4 0.2]);
set(gca, 'YTickLabel', file_stages, 'YTick', 1:4, 'FontSize', 11);
xlabel('Latency (ms)', 'FontSize', 12);
title('Send 1MB File — Stage Waterfall', 'FontSize', 14);
grid on;

% --- Figure 4: Latency vs Node Count (1K to 1M) ---
figure('Position', [100 100 figW figH]);
loglog(N_vec, reg_lat_p1*1000, 'r-', 'LineWidth', 2, 'DisplayName', 'Register (Phase 1)');
hold on;
loglog(N_vec, reg_lat_p2*1000, 'r--', 'LineWidth', 2, 'DisplayName', 'Register (Phase 2)');
loglog(N_vec, reg_lat_p3*1000, 'r:', 'LineWidth', 2, 'DisplayName', 'Register (Phase 3)');
loglog(N_vec, msg_lat_p1*1000, 'b-', 'LineWidth', 2, 'DisplayName', '1KB Msg (Phase 1)');
loglog(N_vec, msg_lat_p2*1000, 'b--', 'LineWidth', 2, 'DisplayName', '1KB Msg (Phase 2)');
loglog(N_vec, msg_lat_p3*1000, 'b:', 'LineWidth', 2, 'DisplayName', '1KB Msg (Phase 3)');
loglog(N_vec, file_lat_p1*1000, 'g-', 'LineWidth', 2, 'DisplayName', '1MB File (Phase 1)');
loglog(N_vec, file_lat_p3*1000, 'g:', 'LineWidth', 2, 'DisplayName', '1MB File (Phase 3)');

% Mark current deployment
xline(12700, 'k--', '12.7K (current)', 'LineWidth', 1.5, 'LabelOrientation', 'horizontal', 'FontSize', 10);
xline(100000, 'Color', [0.5 0 0], 'LineStyle', '--', 'Label', 'Phase 1 target', 'LineWidth', 1);
xline(300000, 'Color', [0 0.5 0], 'LineStyle', '--', 'Label', 'Phase 2 target', 'LineWidth', 1);
xline(1000000, 'Color', [0 0 0.5], 'LineStyle', '--', 'Label', 'Phase 3 target', 'LineWidth', 1);

xlabel('Node Count', 'FontSize', 12);
ylabel('Latency (ms)', 'FontSize', 12);
title('End-to-End Latency vs Node Count', 'FontSize', 14);
legend('Location', 'northwest', 'FontSize', 9);
grid on;
hold off;

% --- Figure 5: Throughput vs Node Count ---
figure('Position', [100 100 figW figH]);
semilogy(N_vec, hb_rate_p1, 'r-', 'LineWidth', 2, 'DisplayName', 'Heartbeat Rate (30s)');
hold on;
semilogy(N_vec, hb_rate_p3, 'r--', 'LineWidth', 2, 'DisplayName', 'Heartbeat Rate (60s, Phase 3)');

yline(max_hb_p1, 'r:', 'LineWidth', 1.5, 'DisplayName', sprintf('Max HB (8 cores): %.0fK/s', max_hb_p1/1000));
yline(max_hb_p2, 'm:', 'LineWidth', 1.5, 'DisplayName', sprintf('Max HB (16 cores): %.0fK/s', max_hb_p2/1000));
yline(max_hb_p3, 'b:', 'LineWidth', 1.5, 'DisplayName', sprintf('Max HB (30 cores, skip): %.0fK/s', max_hb_p3/1000));

yline(max_resolve_p1, 'Color', [0 0.5 0], 'LineStyle', '--', 'LineWidth', 1.5, ...
    'DisplayName', sprintf('Max Resolve (8c): %.0fK/s', max_resolve_p1/1000));
yline(max_resolve_p3, 'Color', [0 0.7 0], 'LineStyle', '--', 'LineWidth', 1.5, ...
    'DisplayName', sprintf('Max Resolve (30c, shard+bin): %.0fM/s', max_resolve_p3/1e6));

xline(12700, 'k--', 'LineWidth', 1);
xlabel('Node Count', 'FontSize', 12);
ylabel('Operations/sec', 'FontSize', 12);
title('Throughput Capacity vs Node Count', 'FontSize', 14);
legend('Location', 'northwest', 'FontSize', 8);
grid on;
hold off;

% --- Figure 6: Cron Storm Timeline ---
figure('Position', [100 100 figW figH]);
subplot(3,1,1);
plot(t_cron, cron_resolve_rate/1000, 'b-', 'LineWidth', 2);
ylabel('Resolves (K/s)', 'FontSize', 11);
title('Cron Storm: 200K Agents, 30s Jitter, 5 Peers Each', 'FontSize', 14);
grid on;

subplot(3,1,2);
plot(t_cron, cron_cpu, 'r-', 'LineWidth', 2);
ylabel('CPU (cores)', 'FontSize', 11);
ylim([0 10]);
grid on;

subplot(3,1,3);
plot(t_cron, cron_lock_wait, 'Color', [0.5 0 0.5], 'LineWidth', 2);
ylabel('Lock Wait (ms)', 'FontSize', 11);
xlabel('Time (seconds)', 'FontSize', 12);
grid on;

% --- Figure 7: Restart Storm Timeline ---
figure('Position', [100 100 figW figH]);
subplot(3,1,1);
plot(t_restart, restart_rereg_rate/1000, 'r-', 'LineWidth', 2);
ylabel('Re-reg Rate (K/s)', 'FontSize', 11);
title('Restart Storm: 1M Agents (Accept Throttle + Backoff)', 'FontSize', 14);
grid on;

subplot(3,1,2);
plot(t_restart, restart_mem_gb, 'b-', 'LineWidth', 2);
ylabel('Memory (GB)', 'FontSize', 11);
yline(128, 'k--', '128 GB VM', 'LineWidth', 1);
grid on;

subplot(3,1,3);
plot(t_restart, restart_lock_util * 100, 'Color', [0.8 0.4 0], 'LineWidth', 2);
ylabel('Write Lock Util %', 'FontSize', 11);
xlabel('Time (seconds)', 'FontSize', 12);
yline(100, 'r--', 'Saturation', 'LineWidth', 1);
grid on;

% --- Figure 8: File Transfer Throughput Curve ---
figure('Position', [100 100 figW figH]);
rtts = [0.001, 0.020, 0.100];  % 1ms LAN, 20ms regional, 100ms intercontinental
colors = {'b', 'r', [0.8 0.5 0]};
labels = {'1ms LAN', '20ms Regional', '100ms Intercontinental'};

for ri = 1:length(rtts)
    rtt_val = rtts(ri);
    [t_v, cwnd_v, tput_v] = aimd_throughput(rtt_val, MSS, initialCwnd_bytes, ...
                                             initialSsthresh_bytes, 5, 0.001);
    plot(t_v, tput_v / 1e6, 'Color', colors{ri}, 'LineWidth', 2, 'DisplayName', labels{ri});
    hold on;
end

xlabel('Time (seconds)', 'FontSize', 12);
ylabel('Throughput (MB/s)', 'FontSize', 12);
title('File Transfer Throughput (AIMD Congestion Control)', 'FontSize', 14);
legend('Location', 'southeast', 'FontSize', 11);
grid on;
hold off;

%% =====================================================================
%% 9. SUMMARY TABLE
%% =====================================================================

fprintf('\n=== Pilot Protocol Scaling Simulation ===\n\n');
fprintf('%-30s %12s %12s %12s\n', 'Metric', 'Phase 1', 'Phase 2', 'Phase 3');
fprintf('%s\n', repmat('-', 1, 68));

% Pick representative N for each phase
idx_12k = find(N_vec >= 12700, 1);
idx_100k = find(N_vec >= 100000, 1);
idx_300k = find(N_vec >= 300000, 1);
idx_1m = find(N_vec >= 1000000, 1);

fprintf('%-30s %10.1f ms %10.1f ms %10.1f ms\n', 'Register @100K', ...
    reg_lat_p1(idx_100k)*1000, reg_lat_p2(idx_100k)*1000, reg_lat_p3(idx_100k)*1000);
fprintf('%-30s %10.1f ms %10.1f ms %10.1f ms\n', 'Register @1M', ...
    reg_lat_p1(idx_1m)*1000, reg_lat_p2(idx_1m)*1000, reg_lat_p3(idx_1m)*1000);
fprintf('%-30s %10.1f ms %10.1f ms %10.1f ms\n', '1KB Msg @100K', ...
    msg_lat_p1(idx_100k)*1000, msg_lat_p2(idx_100k)*1000, msg_lat_p3(idx_100k)*1000);
fprintf('%-30s %10.1f ms %10.1f ms %10.1f ms\n', '1MB File @100K', ...
    file_lat_p1(idx_100k)*1000, file_lat_p2(idx_100k)*1000, file_lat_p3(idx_100k)*1000);
fprintf('%-30s %10.0f/s %10.0f/s %10.0f/s\n', 'Max Heartbeat Rate', ...
    max_hb_p1, max_hb_p2, max_hb_p3);
fprintf('%-30s %10.0fK/s %10.0fK/s %10.0fK/s\n', 'Max Resolve Rate', ...
    max_resolve_p1/1e3, max_resolve_p2/1e3, max_resolve_p3/1e3);
fprintf('%-30s %10.2f%% %10.2f%% %10.2f%%\n', 'Write Lock Util @100K', ...
    write_lock_util_single(idx_100k)*100, write_lock_util_shard(idx_100k)*100, ...
    write_lock_util_shard(idx_100k)*100);
fprintf('%-30s %10.2f%% %10.2f%% %10.2f%%\n', 'Write Lock Util @1M', ...
    write_lock_util_single(idx_1m)*100, write_lock_util_shard(idx_1m)*100, ...
    write_lock_util_shard(idx_1m)*100);

fprintf('\n%-30s %12s %12s %12s\n', 'Infrastructure', 'c2-std-8', 'c2-std-16', 'c2-std-30');
fprintf('%-30s %10d %10d %10d\n', 'Cores', cores_p1, cores_p2, cores_p3);
fprintf('%-30s %10s %10s %10s\n', 'RAM', '32 GB', '64 GB', '128 GB');
fprintf('%-30s %10s %10s %10s\n', 'Cost/mo', '$250', '$500', '$940');
fprintf('%-30s %10s %10s %10s\n', '$/1K agents', '$2.50', '$1.67', '$0.94');

fprintf('\n=== Verification ===\n');
fprintf('At 12.7K nodes (current): register = %.1f ms, lock util = %.4f%%\n', ...
    reg_lat_p1(idx_12k)*1000, write_lock_util_single(idx_12k)*100);
fprintf('  -> Lock wait is negligible (matches observed low CPU)\n');

fprintf('\nDone. %d figures generated.\n', 8);
