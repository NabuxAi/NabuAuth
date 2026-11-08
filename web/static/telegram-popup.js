// Keep Telegram authorization in a separate window. The original tab retains
// its Nabu OAuth state and resumes only after the server starts its session.
(function () {
  var trigger = document.querySelector('[data-telegram-popup]');
  var form = document.querySelector('form[action="/login"]');
  var codeButton = form && form.querySelector('[data-telegram-code]');
  var identifier = form && form.querySelector('[name="identifier"]');
  if (codeButton && identifier) {
    var refreshCodeOption = function () {
      var text = identifier.value.trim();
      codeButton.hidden = !(/[0-9]/.test(text) && /^[+0-9().\s-]+$/.test(text));
    };
    identifier.addEventListener('input', refreshCodeOption);
    refreshCodeOption();
  }

  if (!trigger) return;
  var popup = null;
  trigger.addEventListener('click', function (event) {
    // Unenhanced navigation remains functional if JS or popups are unavailable.
    event.preventDefault();
    var url = new URL(trigger.href, window.location.href);
    url.searchParams.set('popup', '1');
    popup = window.open(url.href, 'nabuauth_telegram', 'popup=yes,width=520,height=720,resizable=yes,scrollbars=yes');
    if (!popup) {
      window.location.assign(trigger.href);
      return;
    }
    popup.focus();
  });

  window.addEventListener('message', function (event) {
    if (!popup || event.source !== popup || event.origin !== window.location.origin ||
        !event.data || event.data.type !== 'nabuauth:telegram:complete') return;
    var url = new URL(trigger.href, window.location.href);
    var next = url.searchParams.get('next') || '/dashboard';
    // A popup never gets to supply a redirect destination.
    if (next.charAt(0) !== '/' || next.charAt(1) === '/') next = '/dashboard';
    window.location.assign(next);
  });
})();
