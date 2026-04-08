/**
 * CyberProbe Threat Map - MCP Apps Client
 * 
 * This script runs inside the MCP Apps iframe and communicates with the host.
 * It receives IP enrichment data and renders an interactive threat map.
 */

import { App } from '@modelcontextprotocol/ext-apps';

declare const L: typeof import('leaflet');

// Types
interface IPEnrichmentData {
  ip: string;
  city: string;
  region: string;
  country: string;
  org: string;
  asn: string;
  abuse_confidence_score: number;
  total_reports: number;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
  lat?: number;
  lng?: number;
}

interface ToolResultContent {
  type: string;
  text?: string;
}

interface ToolResult {
  content?: ToolResultContent[];
  enrichmentData?: IPEnrichmentData[];
}

// Country coordinates for geolocation fallback
const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  'AT': { lat: 48.2082, lng: 16.3738 },
  'SI': { lat: 46.0569, lng: 14.5058 },
  'US': { lat: 39.8283, lng: -98.5795 },
  'GB': { lat: 51.5074, lng: -0.1278 },
  'DE': { lat: 52.5200, lng: 13.4050 },
  'FR': { lat: 48.8566, lng: 2.3522 },
  'NL': { lat: 52.3676, lng: 4.9041 },
  'RU': { lat: 55.7558, lng: 37.6173 },
  'CN': { lat: 39.9042, lng: 116.4074 },
};

// DOM Elements
const loadingEl = document.getElementById('loading')!;
const mapEl = document.getElementById('map')!;
const ipListEl = document.getElementById('ip-list')!;
const criticalCountEl = document.getElementById('critical-count')!;
const highCountEl = document.getElementById('high-count')!;
const cleanCountEl = document.getElementById('clean-count')!;

// Map instance
let map: L.Map | null = null;
let markers: L.Marker[] = [];

// Initialize MCP App
const app = new App({
  name: 'CyberProbe Threat Map',
  version: '2.0.0',
});

// Handle theme changes from host
app.onthemechange = (theme) => {
  document.documentElement.setAttribute('data-theme', theme.mode);
};

// Handle tool results from server
app.ontoolresult = (result: ToolResult & { _meta?: { enrichmentData?: IPEnrichmentData[] } }) => {
  console.log('Received tool result:', result);
  
  // Extract enrichment data from result._meta (MCP Apps pattern) or directly
  const enrichmentData = result._meta?.enrichmentData || result.enrichmentData || [];
  
  if (enrichmentData.length > 0) {
    renderMap(enrichmentData);
  } else {
    // Try to parse from text content if enrichmentData not directly available
    const textContent = result.content?.find(c => c.type === 'text')?.text;
    if (textContent) {
      try {
        const parsed = JSON.parse(textContent);
        if (Array.isArray(parsed)) {
          renderMap(parsed);
        }
      } catch {
        console.warn('Text content is not JSON, checking for embedded data');
        // Data may not be available - show friendly message
        loadingEl.textContent = 'Analysis complete - see summary above';
      }
    } else {
      loadingEl.textContent = 'No threat data received';
    }
  }
};

/**
 * Get severity level from abuse score
 */
function getSeverity(score: number): 'critical' | 'high' | 'medium' | 'clean' {
  if (score >= 90) return 'critical';
  if (score >= 75) return 'high';
  if (score >= 25) return 'medium';
  return 'clean';
}

/**
 * Get coordinates for an IP
 */
function getCoords(ip: IPEnrichmentData): { lat: number; lng: number } {
  if (ip.lat && ip.lng) {
    return { lat: ip.lat, lng: ip.lng };
  }
  return COUNTRY_COORDS[ip.country] || { lat: 0, lng: 0 };
}

/**
 * Create a custom marker icon based on severity
 */
function createMarkerIcon(severity: string): L.DivIcon {
  const colors: Record<string, string> = {
    critical: '#f85149',
    high: '#d29922',
    medium: '#e3b341',
    clean: '#3fb950',
  };
  
  const color = colors[severity] || colors.clean;
  const size = severity === 'critical' ? 16 : 12;
  
  return L.divIcon({
    className: 'custom-marker',
    html: `<div style="
      width: ${size}px;
      height: ${size}px;
      background: ${color};
      border-radius: 50%;
      border: 2px solid rgba(255,255,255,0.9);
      box-shadow: 0 0 12px ${color}, 0 0 24px ${color}40;
    "></div>`,
    iconSize: [size, size],
    iconAnchor: [size / 2, size / 2],
  });
}

/**
 * Render the threat map with IP data
 */
function renderMap(ips: IPEnrichmentData[]): void {
  // Hide loading
  loadingEl.style.display = 'none';
  
  // Calculate stats
  const stats = {
    critical: ips.filter(ip => ip.abuse_confidence_score >= 90).length,
    high: ips.filter(ip => ip.abuse_confidence_score >= 75 && ip.abuse_confidence_score < 90).length,
    clean: ips.filter(ip => ip.abuse_confidence_score < 25).length,
  };
  
  criticalCountEl.textContent = String(stats.critical);
  highCountEl.textContent = String(stats.high);
  cleanCountEl.textContent = String(stats.clean);
  
  // Initialize map if not already done
  if (!map) {
    map = L.map(mapEl, {
      center: [48, 14],
      zoom: 4,
      zoomControl: true,
    });
    
    // Use OpenStreetMap standard tiles for better visibility
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19,
    }).addTo(map);
  }
  
  // Clear existing markers
  markers.forEach(m => m.remove());
  markers = [];
  
  // Clear IP list
  ipListEl.innerHTML = '';
  
  // Add markers and cards for each IP
  const bounds: L.LatLngBounds = L.latLngBounds([]);
  
  ips.forEach((ip, index) => {
    const coords = getCoords(ip);
    const severity = getSeverity(ip.abuse_confidence_score);
    
    // Skip invalid coordinates
    if (coords.lat === 0 && coords.lng === 0) return;
    
    // Add slight offset for overlapping markers
    const offset = index * 0.02;
    const adjustedCoords: [number, number] = [coords.lat + offset, coords.lng + offset];
    
    // Create marker
    const marker = L.marker(adjustedCoords, {
      icon: createMarkerIcon(severity),
    }).addTo(map!);
    
    // Popup content
    const popupHtml = `
      <div class="popup-content">
        <h3>${ip.ip}</h3>
        <p><span class="label">Location:</span> ${ip.city}, ${ip.country}</p>
        <p><span class="label">Organization:</span> ${ip.org}</p>
        <p><span class="label">ASN:</span> ${ip.asn}</p>
        <p><span class="label">Abuse Score:</span> <strong style="color: ${severity === 'critical' ? '#f85149' : '#d29922'}">${ip.abuse_confidence_score}%</strong></p>
        <p><span class="label">Reports:</span> ${ip.total_reports}</p>
      </div>
    `;
    
    marker.bindPopup(popupHtml, { maxWidth: 280 });
    markers.push(marker);
    bounds.extend(adjustedCoords);
    
    // Create sidebar card
    const card = document.createElement('div');
    card.className = `ip-card ${severity}`;
    card.innerHTML = `
      <div class="ip-header">
        <span class="ip-address">${ip.ip}</span>
        <span class="risk-badge ${severity}">${severity}</span>
      </div>
      <div class="ip-details">
        <p>${ip.city}, ${ip.country}</p>
        <p>${ip.org}</p>
      </div>
      <div class="abuse-bar">
        <div class="abuse-fill ${severity}" style="width: ${ip.abuse_confidence_score}%"></div>
      </div>
    `;
    
    // Click to zoom to marker
    card.addEventListener('click', () => {
      map!.setView(adjustedCoords, 8);
      marker.openPopup();
    });
    
    ipListEl.appendChild(card);
  });
  
  // Fit map to show all markers
  if (markers.length > 0) {
    map.fitBounds(bounds, { padding: [50, 50] });
  }
}

// Connect to host
app.connect().catch((err) => {
  console.error('Failed to connect to MCP host:', err);
  loadingEl.textContent = 'Failed to connect';
});

// Export for debugging
(window as any).cyberprobeApp = app;
