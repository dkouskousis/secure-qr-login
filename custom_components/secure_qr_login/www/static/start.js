(function () {
  'use strict';

  var state = document.getElementById('state');
  var qrBox = document.getElementById('qr');
  var progress = document.getElementById('progress');

  var sessionId = '';
  var deviceSecret = '';
  var qrTimer = null;
  var pollTimer = null;
  var qrLifetime = 10;
  var externalAuthCallback = null;

  function currentOrigin() {
    if (window.location.origin) {
      return window.location.origin;
    }
    return window.location.protocol + '//' + window.location.host;
  }

  function parseJson(text) {
    try {
      return JSON.parse(text || '{}');
    } catch (err) {
      return {};
    }
  }

  function request(method, url, body, headers, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    xhr.setRequestHeader('Cache-Control', 'no-store');

    var key;
    if (headers) {
      for (key in headers) {
        if (Object.prototype.hasOwnProperty.call(headers, key)) {
          xhr.setRequestHeader(key, headers[key]);
        }
      }
    }

    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) {
        return;
      }
      callback(null, xhr);
    };

    xhr.onerror = function () {
      callback(new Error('network_error'), xhr);
    };

    try {
      xhr.send(body === undefined || body === null ? null : body);
    } catch (err) {
      callback(err, xhr);
    }
  }

  function postJson(url, body, callback) {
    request(
      'POST',
      url,
      JSON.stringify(body || {}),
      {'Content-Type': 'application/json'},
      callback
    );
  }

  function candidateWindows() {
    var windows = [window];

    try {
      if (window.parent && window.parent !== window) {
        windows.push(window.parent);
      }
    } catch (err) {}

    try {
      if (window.top && window.top !== window && window.top !== window.parent) {
        windows.push(window.top);
      }
    } catch (err) {}

    return windows;
  }

  function browserTokens() {
    var windows = candidateWindows();
    var i;
    var target;
    var memory;
    var raw;
    var stored;

    for (i = 0; i < windows.length; i += 1) {
      target = windows[i];

      try {
        memory = target.__tokenCache && target.__tokenCache.tokens;
        if (memory && (memory.access_token || memory.refresh_token)) {
          return memory;
        }
      } catch (err) {}

      try {
        raw = target.localStorage
          ? target.localStorage.getItem('hassTokens')
          : null;
        if (raw) {
          stored = JSON.parse(raw);
          if (stored && (stored.access_token || stored.refresh_token)) {
            return stored;
          }
        }
      } catch (err) {}
    }

    return null;
  }

  function companionBridgeWindow() {
    var windows = candidateWindows();
    var i;
    var target;

    for (i = 0; i < windows.length; i += 1) {
      target = windows[i];
      try {
        if (
          target.externalAppV2
          || target.externalApp
          || (
            target.webkit
            && target.webkit.messageHandlers
            && target.webkit.messageHandlers.getExternalAuth
          )
        ) {
          return target;
        }
      } catch (err) {}
    }

    return null;
  }

  function installExternalAuthCallback() {
    var windows = candidateWindows();
    var i;

    function callback(success, data) {
      if (externalAuthCallback) {
        externalAuthCallback(Boolean(success), data || null);
      }
    }

    for (i = 0; i < windows.length; i += 1) {
      try {
        windows[i].externalAuthSetToken = callback;
      } catch (err) {}
    }
  }

  function requestExternalAuth(callback) {
    var bridge = companionBridgeWindow();
    var settled = false;
    var timeout;
    var payload;

    if (!bridge) {
      callback(null);
      return;
    }

    timeout = setTimeout(function () {
      if (settled) {
        return;
      }
      settled = true;
      externalAuthCallback = null;
      callback(null);
    }, 5000);

    externalAuthCallback = function (success, data) {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timeout);
      externalAuthCallback = null;

      if (success && data && data.access_token) {
        callback({access_token: data.access_token});
      } else {
        callback(null);
      }
    };

    payload = {callback: 'externalAuthSetToken', force: false};

    try {
      if (bridge.externalAppV2) {
        bridge.externalAppV2.postMessage(JSON.stringify({
          type: 'getExternalAuth',
          payload: payload
        }));
        return;
      }

      if (bridge.externalApp) {
        bridge.externalApp.getExternalAuth(JSON.stringify(payload));
        return;
      }

      bridge.webkit.messageHandlers.getExternalAuth.postMessage(payload);
    } catch (err) {
      clearTimeout(timeout);
      externalAuthCallback = null;
      callback(null);
    }
  }

  function tokenIsValid(accessToken, callback) {
    if (!accessToken) {
      callback(false);
      return;
    }

    request(
      'GET',
      '/api/',
      null,
      {'Authorization': 'Bearer ' + accessToken},
      function (err, xhr) {
        callback(!err && xhr && xhr.status >= 200 && xhr.status < 300);
      }
    );
  }

  function refreshBrowserToken(tokens, callback) {
    var clientId;
    var body;

    if (!tokens || !tokens.refresh_token) {
      callback(null);
      return;
    }

    clientId = tokens.clientId || (currentOrigin() + '/');
    body =
      'grant_type=refresh_token'
      + '&refresh_token=' + encodeURIComponent(tokens.refresh_token)
      + '&client_id=' + encodeURIComponent(clientId);

    request(
      'POST',
      '/auth/token',
      body,
      {'Content-Type': 'application/x-www-form-urlencoded'},
      function (err, xhr) {
        var data;
        var expiresIn;
        var updated = {};
        var key;

        if (
          err
          || !xhr
          || xhr.status < 200
          || xhr.status >= 300
        ) {
          callback(null);
          return;
        }

        data = parseJson(xhr.responseText);
        if (!data.access_token) {
          callback(null);
          return;
        }

        for (key in tokens) {
          if (Object.prototype.hasOwnProperty.call(tokens, key)) {
            updated[key] = tokens[key];
          }
        }

        expiresIn = data.expires_in || 1800;
        updated.hassUrl = currentOrigin();
        updated.clientId = clientId;
        updated.access_token = data.access_token;
        updated.refresh_token = data.refresh_token || tokens.refresh_token;
        updated.expires_in = expiresIn;
        updated.expires = Date.now() + expiresIn * 1000;

        try {
          localStorage.setItem('hassTokens', JSON.stringify(updated));
        } catch (storageErr) {}

        callback(updated);
      }
    );
  }

  function alreadyAuthenticated(callback) {
    var stored = browserTokens();

    installExternalAuthCallback();

    if (stored && stored.access_token) {
      tokenIsValid(stored.access_token, function (valid) {
        if (valid) {
          callback(true);
          return;
        }
        checkRefresh();
      });
      return;
    }

    checkRefresh();

    function checkRefresh() {
      if (stored && stored.refresh_token) {
        refreshBrowserToken(stored, function (refreshed) {
          if (refreshed && refreshed.access_token) {
            tokenIsValid(refreshed.access_token, function (valid) {
              if (valid) {
                callback(true);
                return;
              }
              checkCompanion();
            });
            return;
          }
          checkCompanion();
        });
        return;
      }

      checkCompanion();
    }

    function checkCompanion() {
      requestExternalAuth(function (tokens) {
        if (!tokens || !tokens.access_token) {
          callback(false);
          return;
        }

        tokenIsValid(tokens.access_token, function (valid) {
          callback(Boolean(valid));
        });
      });
    }
  }

  function redirectToHome() {
    clearInterval(qrTimer);
    clearInterval(pollTimer);
    state.className = 'ok';
    state.textContent = 'Already signed in. Opening Home Assistant...';
    window.location.replace('/');
  }

  function fail(text) {
    state.className = 'error';
    state.textContent = text;
    clearInterval(qrTimer);
    clearInterval(pollTimer);
  }

  function arrayContains(values, value) {
    var i;
    for (i = 0; i < values.length; i += 1) {
      if (values[i] === value) {
        return true;
      }
    }
    return false;
  }

  function requestError(data, fallback) {
    if (!data) {
      return fallback;
    }

    if (data.error === 'disabled') {
      return 'QR Login is disabled.';
    }
    if (data.error === 'session_locked') {
      return 'This login request was locked after repeated invalid secret attempts.';
    }
    if (data.error === 'pending_limit_reached') {
      return 'Too many QR login requests are already pending.';
    }
    if (data.error === 'origin_rejected') {
      return 'This request was rejected by the same-origin security policy.';
    }
    if (data.error === 'country_not_allowed') {
      if (data.reason === 'nabu_client_ip_unavailable') {
        return 'Country restriction is enabled, but Nabu Casa did not provide a usable public client IP.';
      }

      if (arrayContains([
        'database_unavailable',
        'lookup_failed',
        'client_ip_missing',
        'client_ip_invalid'
      ], data.reason)) {
        return 'Country restriction is enabled, but local GeoIP resolution is unavailable.';
      }

      return 'QR Login is not allowed from country '
        + (data.country || 'unknown')
        + '.';
    }

    return fallback;
  }

  function animateProgress() {
    progress.style.transition = 'none';
    progress.style.transform = 'scaleX(1)';

    // Force style application before starting the transition. This avoids the
    // Web Animations API, which is missing on some Samsung/Tizen WebViews.
    void progress.offsetWidth;

    progress.style.transition =
      'transform ' + qrLifetime + 's linear';
    progress.style.transform = 'scaleX(0)';
  }

  function rotateQr() {
    postJson('/api/secure_qr_login/qr', {
      session_id: sessionId,
      device_secret: deviceSecret
    }, function (err, xhr) {
      var data;

      if (
        err
        || !xhr
        || xhr.status < 200
        || xhr.status >= 300
      ) {
        data = xhr ? parseJson(xhr.responseText) : {};
        fail(requestError(data, 'Unable to refresh QR code.'));
        return;
      }

      // The SVG is generated by this integration using Segno and contains no
      // user-controlled markup. Injecting it directly avoids Blob URLs and
      // Response.blob(), both problematic on older TV browser engines.
      qrBox.innerHTML = xhr.responseText;
      animateProgress();
    });
  }

  function poll() {
    postJson('/api/secure_qr_login/status', {
      session_id: sessionId,
      device_secret: deviceSecret
    }, function (err, xhr) {
      var data;
      var expiresIn;
      var tokenState;

      if (err || !xhr) {
        return;
      }

      data = parseJson(xhr.responseText);

      if (xhr.status < 200 || xhr.status >= 300) {
        if (arrayContains(
          ['disabled', 'session_not_found', 'session_locked'],
          data.error
        )) {
          fail(requestError(data, 'Login window closed or expired.'));
        }
        return;
      }

      if (data.status === 'denied') {
        fail('Login denied.');
        return;
      }
      if (data.status !== 'approved') {
        return;
      }

      clearInterval(qrTimer);
      clearInterval(pollTimer);

      expiresIn = data.token_expires_in || 1800;
      tokenState = {
        hassUrl: currentOrigin(),
        clientId: currentOrigin() + '/',
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_in: expiresIn,
        expires: Date.now() + expiresIn * 1000
      };

      try {
        localStorage.setItem('hassTokens', JSON.stringify(tokenState));
      } catch (storageErr) {
        fail('Login approved, but this device cannot store the Home Assistant session.');
        return;
      }

      state.className = 'ok';
      state.textContent = 'Approved. Opening Home Assistant...';
      setTimeout(function () {
        window.location.replace('/');
      }, 500);
    });
  }

  function beginLogin() {
    state.textContent = 'Starting secure login session...';

    postJson('/api/secure_qr_login/start', {}, function (err, xhr) {
      var data;

      if (
        err
        || !xhr
        || xhr.status < 200
        || xhr.status >= 300
      ) {
        data = xhr ? parseJson(xhr.responseText) : {};
        fail(requestError(data, 'Unable to start login session.'));
        return;
      }

      data = parseJson(xhr.responseText);
      sessionId = data.session_id || '';
      deviceSecret = data.device_secret || '';
      qrLifetime = data.qr_lifetime || 10;

      if (!sessionId || !deviceSecret) {
        fail('Invalid response while starting Secure QR Login.');
        return;
      }

      rotateQr();
      qrTimer = setInterval(rotateQr, qrLifetime * 1000);
      pollTimer = setInterval(poll, 2000);
    });
  }

  function init() {
    state.textContent = 'Checking existing Home Assistant session...';

    alreadyAuthenticated(function (authenticated) {
      if (authenticated) {
        redirectToHome();
        return;
      }
      beginLogin();
    });
  }

  init();
}());
