<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NabuAuth — Central Ecosystem Launcher</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent: #38bdf8;
            --accent-hover: #0284c7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        body {
            margin: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 40px 20px;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #334155;
        }
        .logo-title h1 {
            margin: 0;
            font-size: 1.8rem;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .user-pill {
            background: #334155;
            padding: 8px 16px;
            border-radius: 999px;
            font-size: 0.9rem;
            color: #e2e8f0;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 24px;
        }
        .app-card {
            background: var(--card-bg);
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 24px;
            transition: transform 0.2s ease, border-color 0.2s ease;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }
        .app-card:hover {
            transform: translateY(-4px);
            border-color: var(--accent);
        }
        .app-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .app-header h3 {
            margin: 0;
            font-size: 1.25rem;
            color: #ffffff;
        }
        .badge {
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .app-desc {
            color: var(--text-muted);
            font-size: 0.92rem;
            line-height: 1.5;
            margin-bottom: 24px;
        }
        .launch-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: var(--accent);
            color: #0f172a;
            font-weight: 700;
            text-decoration: none;
            padding: 12px;
            border-radius: 10px;
            transition: background 0.2s ease;
        }
        .launch-btn:hover {
            background: var(--accent-hover);
            color: #ffffff;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <h1>🔐 NabuAuth Portal</h1>
            </div>
            <div class="user-pill">
                Single Sign-On Active · Central Nabu Account
            </div>
        </header>

        <h2 style="margin-bottom: 20px; font-weight: 600;">Nabu Ecosystem Applications</h2>
        <div class="grid">
            @foreach(\App\Services\EcosystemAppRegistry::all() as $app)
                <div class="app-card">
                    <div>
                        <div class="app-header">
                            <h3>{{ $app['name'] }}</h3>
                            <span class="badge">{{ $app['badge'] }}</span>
                        </div>
                        <p class="app-desc">{{ $app['description'] }}</p>
                    </div>
                    <a href="{{ $app['sso_url'] }}" class="launch-btn" target="_blank">
                        Launch {{ $app['name'] }} ➔
                    </a>
                </div>
            @endforeach
        </div>
    </div>
</body>
</html>
