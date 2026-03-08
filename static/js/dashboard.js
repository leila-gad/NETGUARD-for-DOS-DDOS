const API = "http://localhost:5000";

let stats       = { total: 0, attacks: 0, benign: 0 };
let chartLabels = [];
let chartData   = [];
let logEntries  = [];

//  CHART  
const ctx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels: chartLabels,
    datasets: [{
      label: 'Attack Confidence',
      data: chartData,
      borderColor: '#00e5ff',
      backgroundColor: 'rgba(0,229,255,0.05)',
      borderWidth: 2,
      pointRadius: 4,
      pointBackgroundColor: [],
      tension: 0.3,
      fill: true,
    }]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color:'#3a6a8a', font:{ family:'Share Tech Mono', size:10 } }, grid: { color:'rgba(13,33,55,0.8)' } },
      y: { min:0, max:1, ticks: { color:'#3a6a8a', font:{ family:'Share Tech Mono', size:10 }, callback: v => (v*100).toFixed(0)+'%' }, grid: { color:'rgba(13,33,55,0.8)' } }
    }
  }
});

//  HEALTH CHECK  
async function checkHealth() {
  try {
    const res  = await fetch(`${API}/health`);
    const data = await res.json();
    document.getElementById('statusDot').style.background = '#00e676';
    document.getElementById('statusText').textContent      = 'API ONLINE';
    document.getElementById('featureCount').textContent    = data.features;
    document.getElementById('apiStatus').textContent       = 'CONNECTED';
  } catch {
    document.getElementById('statusDot').style.background = '#ff1744';
    document.getElementById('statusText').textContent      = 'API OFFLINE';
    document.getElementById('apiStatus').textContent       = 'OFFLINE';
  }
}

//  GET FORM VALUES  
// Reads the 12 visible inputs and derives the remaining 56 features
// so the model always receives a realistic 68-feature flow profile
function getFeatures() {
  const dst_port  = +document.getElementById('f_dst_port').value;
  const duration  = +document.getElementById('f_flow_dur').value;
  const fwd_pkts  = +document.getElementById('f_fwd_pkts').value;
  const bwd_pkts  = +document.getElementById('f_bwd_pkts').value;
  const flow_bps  = +document.getElementById('f_flow_bps').value;
  const flow_pps  = +document.getElementById('f_flow_pps').value;
  const syn       = +document.getElementById('f_syn').value;
  const rst       = +document.getElementById('f_rst').value;
  const psh       = +document.getElementById('f_psh').value;
  const ack       = +document.getElementById('f_ack').value;
  const avg_pkt   = +document.getElementById('f_avg_pkt').value;
  const init_win  = +document.getElementById('f_init_win').value;

  // Derive realistic packet length stats from avg_pkt
  const pkt_max  = Math.round(avg_pkt * 1.5);
  const pkt_min  = Math.round(avg_pkt * 0.3);
  const pkt_std  = Math.round(avg_pkt * 0.2);
  const pkt_var  = pkt_std * pkt_std;

  // Derive total bytes from avg packet size × packet counts
  const total_fwd_bytes = Math.round(avg_pkt * fwd_pkts);
  const total_bwd_bytes = Math.round(avg_pkt * bwd_pkts * 0.8);

  // Derive IAT (inter-arrival time) from duration and packet count
  const total_pkts   = fwd_pkts + bwd_pkts || 1;
  const iat_mean     = duration / total_pkts;
  const iat_std      = iat_mean * 0.3;
  const iat_max      = iat_mean * 2;
  const iat_min      = iat_mean * 0.1;

  // Derive per-direction IAT
  const fwd_iat_mean = fwd_pkts > 1 ? duration / fwd_pkts : 0;
  const bwd_iat_mean = bwd_pkts > 1 ? duration / bwd_pkts : 0;

  // Header lengths (typical TCP = 20 bytes)
  const fwd_hdr = fwd_pkts * 20;
  const bwd_hdr = bwd_pkts * 20;

  // Subflow = same as flow (single subflow)
  const subflow_fwd_pkts  = fwd_pkts;
  const subflow_fwd_bytes = total_fwd_bytes;
  const subflow_bwd_pkts  = bwd_pkts;
  const subflow_bwd_bytes = total_bwd_bytes;

  return {
    //  Visible form fields 
    "Destination Port"          : dst_port,
    "Flow Duration"             : duration,
    "Total Fwd Packets"         : fwd_pkts,
    "Total Backward Packets"    : bwd_pkts,
    "Flow Bytes/s"              : flow_bps,
    "Flow Packets/s"            : flow_pps,
    "SYN Flag Count"            : syn,
    "RST Flag Count"            : rst,
    "PSH Flag Count"            : psh,
    "ACK Flag Count"            : ack,
    "Average Packet Size"       : avg_pkt,
    "Init_Win_bytes_forward"    : init_win,

    //  Derived packet length features 
    "Total Length of Fwd Packets" : total_fwd_bytes,
    "Total Length of Bwd Packets" : total_bwd_bytes,
    "Fwd Packet Length Max"       : pkt_max,
    "Fwd Packet Length Min"       : pkt_min,
    "Fwd Packet Length Mean"      : avg_pkt,
    "Fwd Packet Length Std"       : pkt_std,
    "Bwd Packet Length Max"       : pkt_max,
    "Bwd Packet Length Min"       : pkt_min,
    "Bwd Packet Length Mean"      : avg_pkt * 0.8,
    "Bwd Packet Length Std"       : pkt_std,
    "Min Packet Length"           : pkt_min,
    "Max Packet Length"           : pkt_max,
    "Packet Length Mean"          : avg_pkt,
    "Packet Length Std"           : pkt_std,
    "Packet Length Variance"      : pkt_var,
    "Avg Fwd Segment Size"        : avg_pkt,
    "Avg Bwd Segment Size"        : avg_pkt * 0.8,

    //  Derived IAT features 
    "Flow IAT Mean"  : iat_mean,
    "Flow IAT Std"   : iat_std,
    "Flow IAT Max"   : iat_max,
    "Flow IAT Min"   : iat_min,
    "Fwd IAT Total"  : duration,
    "Fwd IAT Mean"   : fwd_iat_mean,
    "Fwd IAT Std"    : fwd_iat_mean * 0.3,
    "Fwd IAT Max"    : fwd_iat_mean * 2,
    "Fwd IAT Min"    : fwd_iat_mean * 0.1,
    "Bwd IAT Total"  : duration,
    "Bwd IAT Mean"   : bwd_iat_mean,
    "Bwd IAT Std"    : bwd_iat_mean * 0.3,
    "Bwd IAT Max"    : bwd_iat_mean * 2,
    "Bwd IAT Min"    : bwd_iat_mean * 0.1,

    //  Header lengths 
    "Fwd Header Length"   : fwd_hdr,
    "Bwd Header Length"   : bwd_hdr,
    "Fwd Header Length.1" : fwd_hdr,

    //  Packet rates 
    "Fwd Packets/s" : fwd_pkts > 0 && duration > 0 ? (fwd_pkts / (duration / 1e6)) : 0,
    "Bwd Packets/s" : bwd_pkts > 0 && duration > 0 ? (bwd_pkts / (duration / 1e6)) : 0,

    //  Flag counts 
    "FIN Flag Count" : ack > 0 ? 1 : 0,
    "URG Flag Count" : 0,
    "ECE Flag Count" : 0,
    "Fwd PSH Flags"  : psh,

    //  Misc 
    "Down/Up Ratio"          : bwd_pkts > 0 ? bwd_pkts / fwd_pkts : 0,
    "Init_Win_bytes_backward": init_win,
    "act_data_pkt_fwd"       : fwd_pkts,
    "min_seg_size_forward"   : pkt_min,

    //  Subflow features 
    "Subflow Fwd Packets" : subflow_fwd_pkts,
    "Subflow Fwd Bytes"   : subflow_fwd_bytes,
    "Subflow Bwd Packets" : subflow_bwd_pkts,
    "Subflow Bwd Bytes"   : subflow_bwd_bytes,

    //  Active / Idle time 
    // Attacks: always active, never idle
    // Normal: short active bursts, long idle gaps
    "Active Mean" : duration * 0.8,
    "Active Std"  : duration * 0.05,
    "Active Max"  : duration,
    "Active Min"  : duration * 0.5,
    "Idle Mean"   : ack > 5 ? duration * 0.3 : 0,
    "Idle Std"    : ack > 5 ? duration * 0.1 : 0,
    "Idle Max"    : ack > 5 ? duration * 0.5 : 0,
    "Idle Min"    : 0,
  };
}

//  SIMULATE BUTTONS 
// Values chosen to match real CICIDS2017 attack/benign statistics
function fillDoS() {
  document.getElementById('f_dst_port').value = 80;
  document.getElementById('f_flow_dur').value = 500;       // very short — ms burst
  document.getElementById('f_fwd_pkts').value = 50000;     // flood
  document.getElementById('f_bwd_pkts').value = 0;         // no response
  document.getElementById('f_flow_bps').value = 9999999;   // saturated bandwidth
  document.getElementById('f_flow_pps').value = 99999;     // extreme packet rate
  document.getElementById('f_syn').value      = 50000;     // SYN flood
  document.getElementById('f_rst').value      = 0;
  document.getElementById('f_psh').value      = 0;
  document.getElementById('f_ack').value      = 0;         // no ACK — incomplete handshakes
  document.getElementById('f_avg_pkt').value  = 44;        // tiny packets
  document.getElementById('f_init_win').value = 0;         // zero window
}

function fillBenign() {
  document.getElementById('f_dst_port').value = 443;
  document.getElementById('f_flow_dur').value = 2000000;   // 2 seconds — normal browsing
  document.getElementById('f_fwd_pkts').value = 12;
  document.getElementById('f_bwd_pkts').value = 10;
  document.getElementById('f_flow_bps').value = 4500;      // normal throughput
  document.getElementById('f_flow_pps').value = 8;         // low packet rate
  document.getElementById('f_syn').value      = 1;         // one handshake
  document.getElementById('f_rst').value      = 0;
  document.getElementById('f_psh').value      = 2;
  document.getElementById('f_ack').value      = 18;        // balanced ACKs
  document.getElementById('f_avg_pkt').value  = 512;       // normal packet size
  document.getElementById('f_init_win').value = 65535;     // full TCP window
}

//  ANALYZE 
async function analyze() {
  const btn     = document.getElementById('btnAnalyze');
  const display = document.getElementById('resultDisplay');

  btn.disabled    = true;
  btn.textContent = 'ANALYZING...';
  display.className = 'result-display';
  display.innerHTML = '<div class="spinner"></div>';

  try {
    const res  = await fetch(`${API}/predict`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify(getFeatures())
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    renderResult(data);
    updateStats(data);
    updateChart(data);
    addToLog(data);

  } catch (err) {
    display.className = 'result-display';
    display.innerHTML = `<div class="result-idle"><div class="idle-icon">⚠</div><p>ERROR: ${err.message}</p></div>`;
  } finally {
    btn.disabled    = false;
    btn.textContent = '▶ ANALYZE FLOW';
  }
}

//  RENDER RESULT 
function renderResult(data) {
  const display = document.getElementById('resultDisplay');
  const conf    = (data.confidence * 100).toFixed(2);
  const isAtk   = data.prediction === 1;
  display.className = `result-display ${isAtk ? 'attack' : 'benign'}`;
  display.innerHTML = `
    <div class="result-content">
      <div class="result-label">${data.label}</div>
      <div class="result-confidence">CONFIDENCE: ${conf}%</div>
      <div class="risk-badge risk-${data.risk_level}">${data.risk_level} RISK</div>
    </div>`;
  const bar = document.getElementById('confBar');
  bar.style.width = (data.confidence * 100) + '%';
  bar.className   = `conf-bar-fill ${isAtk ? 'danger' : 'safe'}`;
  document.getElementById('confLabel').textContent = conf + '%';
}

//  STATS 
function updateStats(data) {
  stats.total++;
  data.prediction === 1 ? stats.attacks++ : stats.benign++;
  document.getElementById('statTotal').textContent   = stats.total;
  document.getElementById('statAttacks').textContent = stats.attacks;
  document.getElementById('statBenign').textContent  = stats.benign;
  document.getElementById('statRate').textContent    = ((stats.attacks / stats.total) * 100).toFixed(1) + '%';
}

//  CHART 
function updateChart(data) {
  const t = new Date().toLocaleTimeString('en', { hour12: false });
  chartLabels.push(t);
  chartData.push(data.confidence);
  if (chartLabels.length > 20) { chartLabels.shift(); chartData.shift(); }
  trafficChart.data.datasets[0].pointBackgroundColor = chartData.map(v => v > 0.5 ? '#ff1744' : '#00e676');
  trafficChart.update();
}

//  LOG 
function addToLog(data) {
  const t = new Date().toLocaleTimeString();
  logEntries.unshift({ time: t, ...data });
  if (logEntries.length > 50) logEntries.pop();
  document.getElementById('logBody').innerHTML = `
    <table class="log-table">
      <thead><tr><th>TIME</th><th>VERDICT</th><th>CONFIDENCE</th><th>RISK</th></tr></thead>
      <tbody>
        ${logEntries.map(e => `
          <tr>
            <td>${e.time}</td>
            <td class="${e.prediction===1?'badge-attack':'badge-benign'}">${e.label}</td>
            <td>${(e.confidence*100).toFixed(2)}%</td>
            <td class="${e.prediction===1?'badge-attack':'badge-benign'}">${e.risk_level}</td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

//  INIT
checkHealth();
setInterval(checkHealth, 10000);