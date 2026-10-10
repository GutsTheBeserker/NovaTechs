/**
 * Active Scanner Popup Controller
 *
 * Coordinates real-time tab analysis, controls scanning indicators,
 * renders explainability cards, reasons, recommendations, and handles
 * restricted browser pages gracefully without fabricating results.
 */

import { SecurityVerdict, ThreatIndicator } from '../shared/types.js';
import { isRestrictedScheme } from '../shared/validators.js';
import { logDiagnostic, extractVerdictSignals } from '../shared/diagnostic_logger.js';

document.addEventListener('DOMContentLoaded', async () => {
  const badgePill = document.getElementById('badge-pill')!;
  const targetDomain = document.getElementById('target-domain')!;
  const instBadge = document.getElementById('inst-badge')!;
  const rescanBtn = document.getElementById('rescan-btn')!;
  const rescanText = document.getElementById('rescan-text')!;
  const scanningIndicator = document.getElementById('scanning-indicator')!;
  const restrictedBox = document.getElementById('restricted-box')!;
  const restrictedDesc = document.getElementById('restricted-desc')!;
  const resultsContainer = document.getElementById('results-container')!;
  const scoreNumber = document.getElementById('score-number')!;
  const scoreCircle = document.getElementById('score-circle')!;
  const riskTierText = document.getElementById('risk-tier-text')!;
  const scanTimestamp = document.getElementById('scan-timestamp')!;
  const recBox = document.getElementById('recommendation-box')!;
  const recText = document.getElementById('recommendation-text')!;
  const factorsList = document.getElementById('factors-list')!;
  const latencyVal = document.getElementById('latency-val')!;
  const viewWarningBtn = document.getElementById('view-warning-btn')!;
  const engineSourceBadge = document.getElementById('engine-source-badge')!;
  const engineModeName = document.getElementById('engine-mode-name')!;
  const breakdownRuleScore = document.getElementById('breakdown-rule-score')!;
  const breakdownMlScore = document.getElementById('breakdown-ml-score')!;
  const trustProfileStatus = document.getElementById('trust-profile-status')!;
  const trustObservationText = document.getElementById('trust-observation-text')!;
  const trustDriftAlert = document.getElementById('trust-drift-alert')!;
  const trustDriftDesc = document.getElementById('trust-drift-desc')!;
  const clearProfilesBtn = document.getElementById('clear-profiles-btn')!;
  const clearStatusMsg = document.getElementById('clear-status-msg')!;

  clearProfilesBtn?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'CLEAR_TRUST_PROFILES' }, () => {
      clearStatusMsg?.classList.remove('hidden');
      if (trustProfileStatus) {
        trustProfileStatus.textContent = 'Learning';
        trustProfileStatus.className = 'trust-status-pill status-learning';
      }
      if (trustObservationText) {
        trustObservationText.textContent = 'Profiles cleared. Learning fresh baselines.';
      }
      trustDriftAlert?.classList.add('hidden');
      setTimeout(() => {
        clearStatusMsg?.classList.add('hidden');
      }, 2500);
    });
  });

  let currentTabId: number | undefined;
  let currentTabUrl: string | undefined;

  // 1. Query active tab
  try {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!activeTab || !activeTab.id || !activeTab.url) {
      showErrorState('No active browser tab found.');
      return;
    }

    currentTabId = activeTab.id;
    currentTabUrl = activeTab.url;

    // Check for restricted internal browser schemes
    if (isRestrictedScheme(currentTabUrl)) {
      renderRestrictedState(currentTabUrl);
      return;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(currentTabUrl);
      targetDomain.textContent = parsedUrl.hostname;
    } catch {
      targetDomain.textContent = currentTabUrl;
    }

    // 2. Query existing analysis or trigger fresh scan
    fetchTabVerdict();
  } catch (err) {
    console.error('[PhishGuard] Tab initialization error:', err);
    showErrorState('Could not initialize tab inspection.');
  }

  // 3. Rescan Button Handler
  rescanBtn.addEventListener('click', () => {
    if (!currentTabId || !currentTabUrl || isRestrictedScheme(currentTabUrl)) return;
    triggerScan();
  });

  function setScanningState(): void {
    scanningIndicator.classList.remove('hidden');
    resultsContainer.classList.add('hidden');
    restrictedBox.classList.add('hidden');
    badgePill.textContent = 'SCANNING';
    badgePill.className = 'badge-pill badge-scanning';
    rescanBtn.setAttribute('disabled', 'true');
    rescanText.textContent = 'Scanning...';
  }

  function clearScanningState(): void {
    scanningIndicator.classList.add('hidden');
    rescanBtn.removeAttribute('disabled');
    rescanText.textContent = 'Rescan';
  }

  function fetchTabVerdict(): void {
    if (!currentTabId) return;

    setScanningState();

    chrome.runtime.sendMessage(
      { type: 'GET_SECURITY_VERDICT', tabId: currentTabId },
      (response) => {
        const verdict: SecurityVerdict | null = response?.payload;

        if (verdict && (verdict.status === 'COMPLETE' || verdict.status === 'INCOMPLETE')) {
          clearScanningState();
          renderVerdict(verdict);
        } else {
          // If no cached verdict yet, trigger scan on demand
          triggerScan();
        }
      }
    );
  }

  function triggerScan(): void {
    if (!currentTabId || !currentTabUrl) return;
    setScanningState();

    logDiagnostic({
      phase: 'SCAN_TRIGGERED',
      url: currentTabUrl,
      tabId: currentTabId,
    });

    chrome.runtime.sendMessage(
      { type: 'TRIGGER_RESCAN', tabId: currentTabId, url: currentTabUrl },
      () => {
        // Poll for updated verdict (max 3 seconds)
        let attempts = 0;
        const interval = setInterval(() => {
          attempts++;
          chrome.runtime.sendMessage(
            { type: 'GET_SECURITY_VERDICT', tabId: currentTabId },
            (resp) => {
              const updatedVerdict: SecurityVerdict | null = resp?.payload;
              if (updatedVerdict && (updatedVerdict.status === 'COMPLETE' || updatedVerdict.status === 'INCOMPLETE')) {
                clearInterval(interval);
                clearScanningState();
                renderVerdict(updatedVerdict);
              } else if (attempts >= 8) {
                clearInterval(interval);
                clearScanningState();
                if (updatedVerdict) {
                  renderVerdict(updatedVerdict);
                } else {
                  showErrorState('Analysis incomplete: Webpage structural features could not be collected. Please refresh the page and try again.');
                }
              }
            }
          );
        }, 350);
      }
    );
  }

  function renderRestrictedState(url: string): void {
    targetDomain.textContent = url.split('/')[0] || 'Internal Page';
    badgePill.textContent = 'RESTRICTED';
    badgePill.className = 'badge-pill badge-idle';
    restrictedBox.classList.remove('hidden');
    restrictedDesc.textContent = `Internal system pages (${url.split(':')[0]}://) are protected and excluded from extension script inspection.`;
    resultsContainer.classList.add('hidden');
    scanningIndicator.classList.add('hidden');
    rescanBtn.classList.add('hidden');
    latencyVal.textContent = '0 ms';
  }

  function showErrorState(msg: string): void {
    clearScanningState();
    badgePill.textContent = 'INCOMPLETE';
    badgePill.className = 'badge-pill badge-incomplete';
    targetDomain.textContent = currentTabUrl ? new URL(currentTabUrl).hostname : 'Unknown Host';
    scoreNumber.textContent = '--';
    scoreCircle.className = 'score-circle unknown-border';
    riskTierText.textContent = 'SCAN INCOMPLETE';
    riskTierText.className = 'risk-tier-title tier-unknown';
    recBox.className = 'recommendation-box';
    recText.textContent = msg;
    resultsContainer.classList.remove('hidden');
    factorsList.innerHTML = `<div class="empty-factors">${msg}</div>`;

    logDiagnostic({
      phase: 'SCAN_INCOMPLETE',
      url: currentTabUrl,
      tabId: currentTabId,
      errorReason: msg,
    });
  }

  function formatTimestamp(ts: number): string {
    const d = new Date(ts);
    return `${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
  }

  function renderVerdict(verdict: SecurityVerdict): void {
    targetDomain.textContent = verdict.fqdn;
    scoreNumber.textContent = verdict.riskScore.toString();
    latencyVal.textContent = `${verdict.latencyMs} ms`;
    scanTimestamp.textContent = `Completed at ${formatTimestamp(verdict.timestamp)}`;

    // Institutional indicator
    if (verdict.isInstitutional) {
      instBadge.classList.remove('hidden');
    } else {
      instBadge.classList.add('hidden');
    }

    // Engine source presentation
    if (verdict.scanSource === 'server_assisted') {
      engineSourceBadge.textContent = 'Server-Assisted ML';
      engineSourceBadge.className = 'engine-source-badge engine-source-server';
      engineModeName.textContent = 'Remote ML + Local Heuristics';
    } else if (verdict.scanSource === 'cached') {
      engineSourceBadge.textContent = 'Cached Server ML';
      engineSourceBadge.className = 'engine-source-badge engine-source-server';
      engineModeName.textContent = 'Cached ML Assessment';
    } else if (verdict.offlineFallback) {
      engineSourceBadge.textContent = 'Offline Fallback';
      engineSourceBadge.className = 'engine-source-badge engine-source-offline';
      engineModeName.textContent = 'Local Engine (Backend Offline)';
    } else {
      engineSourceBadge.textContent = 'Local Heuristics';
      engineSourceBadge.className = 'engine-source-badge engine-source-local';
      engineModeName.textContent = 'Local Heuristics Engine';
    }

    // Breakdown scoring
    if (verdict.compositeBreakdown) {
      breakdownRuleScore.textContent = `Rules: ${verdict.compositeBreakdown.ruleScore} / 100`;
      if (verdict.compositeBreakdown.mlScore !== null) {
        const mlVer = verdict.mlAssessment?.model_version ? ` (${verdict.mlAssessment.model_version})` : '';
        breakdownMlScore.textContent = `ML Model${mlVer}: ${verdict.compositeBreakdown.mlScore} / 100`;
        breakdownMlScore.classList.remove('hidden');
      } else {
        breakdownMlScore.classList.add('hidden');
      }
    } else {
      breakdownRuleScore.textContent = `Rules: ${verdict.riskScore} / 100`;
      breakdownMlScore.classList.add('hidden');
    }

    // Adaptive Trust Profile presentation
    if (verdict.trustProfileSummary && trustProfileStatus) {
      const tp = verdict.trustProfileSummary;
      if (tp.hasDrift) {
        trustProfileStatus.textContent = 'Drift Detected';
        trustProfileStatus.className = 'trust-status-pill status-drift';
        if (trustObservationText) {
          trustObservationText.textContent = `Baseline established across ${tp.observationCount} visits`;
        }
        trustDriftAlert?.classList.remove('hidden');
        if (trustDriftDesc) {
          trustDriftDesc.textContent =
            tp.driftDetails?.join(' ') || 'Behavioral divergence from established baseline.';
        }
      } else if (tp.baselineEstablished) {
        trustProfileStatus.textContent = 'Baseline Established';
        trustProfileStatus.className = 'trust-status-pill status-established';
        if (trustObservationText) {
          trustObservationText.textContent = `Profiled across ${tp.observationCount} verified visits`;
        }
        trustDriftAlert?.classList.add('hidden');
      } else {
        trustProfileStatus.textContent = 'Learning';
        trustProfileStatus.className = 'trust-status-pill status-learning';
        if (trustObservationText) {
          trustObservationText.textContent = `Observed: ${tp.observationCount} visit(s) (Baseline requires 3+)`;
        }
        trustDriftAlert?.classList.add('hidden');
      }
    } else if (trustProfileStatus) {
      trustProfileStatus.textContent = 'Learning';
      trustProfileStatus.className = 'trust-status-pill status-learning';
      if (trustObservationText) {
        trustObservationText.textContent = 'Gathering baseline observations (requires 3+)';
      }
      trustDriftAlert?.classList.add('hidden');
    }

    // Reset classes
    badgePill.className = 'badge-pill';
    scoreCircle.className = 'score-circle';
    riskTierText.className = 'risk-tier-title';
    recBox.className = 'recommendation-box';

    // Tier specific presentation
    if (verdict.status === 'INCOMPLETE' || verdict.status === 'ERROR' || verdict.riskTier === 'UNKNOWN') {
      badgePill.textContent = 'INCOMPLETE';
      badgePill.classList.add('badge-incomplete');
      scoreCircle.classList.add('unknown-border');
      riskTierText.textContent = 'SCAN INCOMPLETE';
      riskTierText.classList.add('tier-unknown');
      viewWarningBtn.classList.add('hidden');
    } else if (verdict.riskTier === 'HIGH') {
      badgePill.textContent = 'HIGH RISK';
      badgePill.classList.add('badge-high');
      scoreCircle.classList.add('high-border');
      riskTierText.textContent = 'HIGH RISK';
      riskTierText.classList.add('tier-high');
      recBox.classList.add('high-alert');
      viewWarningBtn.classList.remove('hidden');
      viewWarningBtn.onclick = () => {
        chrome.runtime.sendMessage({
          type: 'OPEN_WARNING_PAGE',
          payload: {
            url: verdict.url,
            riskScore: verdict.riskScore,
            factors: verdict.primaryFactors,
          },
        });
      };
    } else if (verdict.riskTier === 'MEDIUM') {
      badgePill.textContent = 'MEDIUM RISK';
      badgePill.classList.add('badge-medium');
      scoreCircle.classList.add('medium-border');
      riskTierText.textContent = 'MEDIUM RISK';
      riskTierText.classList.add('tier-medium');
      recBox.classList.add('medium-alert');
      viewWarningBtn.classList.add('hidden');
    } else {
      badgePill.textContent = 'LOW RISK';
      badgePill.classList.add('badge-low');
      riskTierText.textContent = 'LOW RISK';
      riskTierText.classList.add('tier-low');
      viewWarningBtn.classList.add('hidden');
    }

    recText.textContent = verdict.recommendation;

    // Render explainability factor cards with reasons & evidence
    renderFactorCards(verdict.primaryFactors);

    resultsContainer.classList.remove('hidden');

    logDiagnostic({
      phase: 'LOCAL_EVALUATION',
      url: verdict.url,
      tabId: currentTabId,
      modulesExecuted: [
        'URL_ANALYSIS',
        ...(verdict.sslSignals ? ['SSL_ANALYSIS'] : []),
        ...(verdict.primaryFactors.some((f) => f.category === 'DOM') ? ['DOM_ANALYSIS'] : []),
        ...(verdict.scanSource === 'server_assisted' ? ['REMOTE_ML_BACKEND'] : []),
      ],
      detectedSignals: extractVerdictSignals(verdict.primaryFactors),
      scoreBreakdown: {
        rawScore: verdict.compositeBreakdown?.ruleScore ?? verdict.riskScore,
        finalScore: verdict.riskScore,
        tier: verdict.riskTier,
        isInstitutional: verdict.isInstitutional,
      },
      remoteStatus: {
        requested: verdict.scanSource === 'server_assisted',
        reason: verdict.scanSource,
        success: verdict.scanSource === 'server_assisted',
        latencyMs: verdict.compositeBreakdown?.serverLatencyMs,
        mlRiskScore: verdict.compositeBreakdown?.mlScore,
      },
    });
  }

  function renderFactorCards(factors: ThreatIndicator[]): void {
    factorsList.innerHTML = '';

    if (!factors || factors.length === 0) {
      factorsList.innerHTML =
        '<div class="empty-factors">No suspicious anomalies or deception markers detected.</div>';
      return;
    }

    factors.forEach((f) => {
      const card = document.createElement('div');
      card.className = 'factor-card';
      card.setAttribute('role', 'listitem');

      // Card Header
      const header = document.createElement('div');
      header.className = 'factor-header';

      const sevPill = document.createElement('span');
      sevPill.className = `severity-pill sev-${f.severity.toLowerCase()}`;
      sevPill.textContent = f.severity;

      const scoreBadge = document.createElement('span');
      scoreBadge.className = 'score-badge';
      if (f.scoreImpact > 0) {
        scoreBadge.textContent = `+${f.scoreImpact} pts`;
      } else {
        scoreBadge.textContent = `${f.scoreImpact} pts`;
        scoreBadge.classList.add('trust-bonus');
      }

      header.appendChild(sevPill);
      header.appendChild(scoreBadge);

      // Description & Reason
      const desc = document.createElement('div');
      desc.className = 'factor-desc';
      desc.textContent = f.description;

      const reason = document.createElement('div');
      reason.className = 'factor-reason';
      reason.textContent = `Reason: ${f.reason}`;

      card.appendChild(header);
      card.appendChild(desc);
      card.appendChild(reason);

      // Optional Evidence
      if (f.evidence) {
        const evidence = document.createElement('div');
        evidence.className = 'factor-evidence';
        evidence.textContent = `Evidence: ${f.evidence}`;
        card.appendChild(evidence);
      }

      factorsList.appendChild(card);
    });
  }
});
