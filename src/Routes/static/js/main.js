document.addEventListener('DOMContentLoaded', () => {
    // Initialize Chart
    const ctx = document.getElementById('timelineChart').getContext('2d');
    let timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts per Hour',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8', stepSize: 1 }
                }
            }
        }
    });

    // Update Time
    function updateTime() {
        const now = new Date();
        document.getElementById('current-time').textContent = now.toLocaleString();
    }
    setInterval(updateTime, 1000);
    updateTime();

    // Fetch Stats
    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            
            document.getElementById('total-alerts-val').textContent = data.total_alerts || 0;
            
            // Top Protocol
            if (data.protocol_distribution) {
                let topProto = '-';
                let maxCount = 0;
                for (const [proto, count] of Object.entries(data.protocol_distribution)) {
                    if (count > maxCount) {
                        maxCount = count;
                        topProto = proto.toUpperCase();
                    }
                }
                document.getElementById('top-protocol-val').textContent = topProto;
            }

            // Update Chart
            if (data.timeline) {
                timelineChart.data.labels = data.timeline.map(t => {
                    const d = new Date(t.hour);
                    return d.getHours() + ':00';
                });
                timelineChart.data.datasets[0].data = data.timeline.map(t => t.count);
                timelineChart.update();
            }

        } catch (e) {
            console.error('Error fetching stats:', e);
        }
    }

    // Fetch Alerts
    async function fetchAlerts() {
        try {
            const res = await fetch('/api/alerts');
            const data = await res.json();
            
            const tbody = document.querySelector('#alerts-table tbody');
            tbody.innerHTML = '';
            
            data.forEach(alert => {
                const tr = document.createElement('tr');
                
                let predictionClass = 'badge-info';
                if (alert.prediction.includes('high') || alert.prediction === 'attack' || alert.prediction !== 'normal') {
                    predictionClass = 'badge-danger';
                }

                tr.innerHTML = `
                    <td>${alert.timestamp}</td>
                    <td>${alert.src_ip}</td>
                    <td>${alert.dst_ip}</td>
                    <td>${alert.protocol.toUpperCase()}</td>
                    <td><span class="badge ${predictionClass}">${alert.prediction}</span></td>
                    <td>${alert.action}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Error fetching alerts:', e);
        }
    }

    // Fetch Blocked IPs
    async function fetchBlocked() {
        try {
            const res = await fetch('/api/blocked');
            const data = await res.json();
            
            document.getElementById('active-blocks-val').textContent = data.length || 0;

            const tbody = document.querySelector('#blocked-table tbody');
            tbody.innerHTML = '';
            
            data.forEach(block => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${block.ip}</strong></td>
                    <td>${block.block_time}</td>
                    <td>${block.expiry_time}</td>
                    <td>
                        <button class="btn" onclick="unblockIp('${block.ip}')">Unblock</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Error fetching blocked IPs:', e);
        }
    }

    // Unblock IP Logic
    window.unblockIp = async function(ip) {
        if (!confirm(`Are you sure you want to unblock ${ip}?`)) return;
        
        try {
            const res = await fetch(`/api/unblock/${ip}`, { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                alert(data.message);
                fetchBlocked(); // Refresh list immediately
            } else {
                alert('Error: ' + data.message);
            }
        } catch (e) {
            alert('Failed to unblock IP.');
        }
    }

    // Initial Load & Polling
    function refreshAll() {
        fetchStats();
        fetchAlerts();
        fetchBlocked();
    }
    
    refreshAll();
    setInterval(refreshAll, 5000); // Poll every 5 seconds
});
