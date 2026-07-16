/**
 * Challenge board indicator - colors the tiles of challenges that have a
 * running container instance for the current user/team.
 *
 * Loaded globally (register_plugin_script); only activates on pages where
 * the challenge board actually renders (it is client-side rendered, so we
 * watch the DOM briefly before giving up).
 */
(function () {
    var API = "/api/v1/containers/running";
    var runningIds = new Set();
    var started = false;

    var style = document.createElement('style');
    style.textContent = [
        '.challenge-button.container-active {',
        '    border: 2px solid #17a2b8 !important;',
        '    box-shadow: 0 0 10px rgba(23, 162, 184, 0.55);',
        '    position: relative;',
        '}',
        '.challenge-button.container-active::after {',
        '    content: "";',
        '    position: absolute;',
        '    top: 8px;',
        '    right: 8px;',
        '    width: 10px;',
        '    height: 10px;',
        '    border-radius: 50%;',
        '    background: #17a2b8;',
        '    animation: container-active-pulse 1.6s infinite;',
        '}',
        '@keyframes container-active-pulse {',
        '    0% { box-shadow: 0 0 0 0 rgba(23, 162, 184, 0.7); }',
        '    70% { box-shadow: 0 0 0 8px rgba(23, 162, 184, 0); }',
        '    100% { box-shadow: 0 0 0 0 rgba(23, 162, 184, 0); }',
        '}'
    ].join('\n');
    document.head.appendChild(style);

    function markButtons() {
        document.querySelectorAll('button.challenge-button[value]').forEach(function (btn) {
            var id = parseInt(btn.getAttribute('value'), 10);
            btn.classList.toggle('container-active', runningIds.has(id));
        });
    }

    function refresh() {
        fetch(API, { headers: { 'Accept': 'application/json' } })
            .then(function (r) { return r.ok ? r.json() : { challenge_ids: [] }; })
            .then(function (data) {
                runningIds = new Set(data.challenge_ids || []);
                markButtons();
            })
            .catch(function () { /* not logged in / CTF not started - ignore */ });
    }

    function start() {
        if (started) return;
        started = true;
        refresh();
        // Periodic refresh (instances expire server-side too)
        setInterval(refresh, 20000);
        // Re-mark when the board re-renders (Alpine redraws on filtering etc.)
        new MutationObserver(markButtons).observe(document.body, { childList: true, subtree: true });
        // Instant update when view.js starts/stops/restarts an instance
        document.addEventListener('containers:changed', refresh);
    }

    // The board renders client-side after page load - watch for it, give up
    // after 20s on pages without a challenge board.
    if (document.querySelector('button.challenge-button')) {
        start();
    } else {
        var bootObserver = new MutationObserver(function () {
            if (document.querySelector('button.challenge-button')) {
                bootObserver.disconnect();
                start();
            }
        });
        bootObserver.observe(document.body, { childList: true, subtree: true });
        setTimeout(function () { if (!started) bootObserver.disconnect(); }, 20000);
    }
})();
