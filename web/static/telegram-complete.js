// The server has already authenticated the Telegram identity and set the
// NabuAuth session cookie. Never send a profile, code, or token to the opener.
(function () {
  var link = document.getElementById('telegram-complete-continue');
  if (!link) return;
  if (window.opener && !window.opener.closed) {
    window.opener.postMessage({type: 'nabuauth:telegram:complete'}, window.location.origin);
    // Give the opener a chance to receive the queued message before closing.
    window.setTimeout(function () { window.close(); }, 250);
  } else {
    // Browsers that isolate popup windows can still complete the sign-in.
    window.location.replace(link.href);
  }
})();
