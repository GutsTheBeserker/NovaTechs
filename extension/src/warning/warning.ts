/**
 * Warning Page Script: Handles user actions on phishing interstitial warning.
 */

document.addEventListener('DOMContentLoaded', () => {
  const goBackBtn = document.getElementById('go-back-btn');
  const proceedBtn = document.getElementById('proceed-btn');

  goBackBtn?.addEventListener('click', () => {
    // Navigate back to browser safety or close tab
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  proceedBtn?.addEventListener('click', () => {
    if (confirm('Warning: This site exhibits active credential theft indicators. Are you sure you wish to proceed?')) {
      window.close();
    }
  });
});
