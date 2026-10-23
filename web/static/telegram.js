// Hands the profile Telegram put in the URL fragment back to the server.
// The fragment never reaches a server on its own, so this is the only way in.
(function () {
  var form = document.getElementById('telegram-return');
  if (!form) return;
  var match = /[#&]tgAuthResult=([^&]+)/.exec(location.hash);
  // Drop the profile from the address bar and history either way.
  history.replaceState(null, '', location.pathname + location.search);
  if (!match || match[1] === 'false') {
    form.querySelector('[data-waiting]').hidden = true;
    form.querySelector('[data-cancelled]').hidden = false;
    return;
  }
  form.elements.result.value = decodeURIComponent(match[1]);
  form.submit();
})();
